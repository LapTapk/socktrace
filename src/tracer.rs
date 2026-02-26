use crate::output::write_sock;
use anyhow::{Context, Result, anyhow};
use nix::sys::ptrace;
use nix::sys::ptrace::Options;
use nix::sys::uio::{RemoteIoVec, process_vm_readv};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd;
use std::collections::HashMap;
use std::io::IoSliceMut;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock, RwLock, RwLockReadGuard, RwLockWriteGuard};

struct Conf {
    sock: Option<String>,
    outdir: PathBuf,
}

static NEW_TRACERS: OnceLock<Mutex<Vec<Tracer>>> = OnceLock::new();
static TRACERS: OnceLock<RwLock<HashMap<unistd::Pid, Tracer>>> = OnceLock::new();
static CONF: OnceLock<Conf> = OnceLock::new();

const SECCOMP_EVENT: i32 = ptrace::Event::PTRACE_EVENT_SECCOMP as i32;
const CLONE_EVENT: i32 = ptrace::Event::PTRACE_EVENT_CLONE as i32;
const FORK_EVENT: i32 = ptrace::Event::PTRACE_EVENT_FORK as i32;
const VFORK_EVENT: i32 = ptrace::Event::PTRACE_EVENT_VFORK as i32;
const EXEC_EVENT: i32 = ptrace::Event::PTRACE_EVENT_EXEC as i32;

enum ContType {
    Cont(unistd::Pid, Option<nix::sys::signal::Signal>),
    Exit,
    Syscall(unistd::Pid, Option<nix::sys::signal::Signal>),
}

#[derive(Clone, Debug)]
struct Socket {
    fd: i32,
    name: Arc<String>,
}

type PerProcFdMap = Arc<RwLock<HashMap<i32, Socket>>>;

fn get_oncelock<T>(lock: &'static OnceLock<T>) -> Result<&'static T> {
    lock.get().ok_or(anyhow!("OnceLock is not initialized"))
}

fn write_rwlock<'a, T>(lock: &'a RwLock<T>) -> Result<RwLockWriteGuard<'a, T>> {
    lock.write().map_err(|e| anyhow!("RwLock poisoned: {e}"))
}

fn read_rwlock<'a, T>(lock: &'a RwLock<T>) -> Result<RwLockReadGuard<'a, T>> {
    lock.read().map_err(|e| anyhow!("RwLock poisoned: {e}"))
}

struct Tracer {
    tid: unistd::Pid,
    tgid: unistd::Pid,
    fd_map: PerProcFdMap,
    after_syscall: bool,
}

impl Tracer {
    pub fn new<'a>(
        tid: unistd::Pid,
        tgid: unistd::Pid,
        fd_map_opt: Option<PerProcFdMap>,
    ) -> Result<Self> {
        let fd_map = match fd_map_opt {
            Some(f) => f,
            None => Arc::new(RwLock::new(HashMap::new())),
        };

        Ok(Self {
            tid,
            tgid,
            fd_map,
            after_syscall: false,
        })
    }

    fn log(&self, msg: &str) -> String {
        let s = format!("[TID: {} TGID: {}] {}", self.tid, self.tgid, msg);
        eprintln!("{}", s);
        s
    }

    fn intercept_sendmsg_recvmsg(
        &mut self,
        regs: libc::user_regs_struct,
        is_sendmsg: bool,
    ) -> Result<ContType> {
        let sock = match self.get_sock(regs)? {
            Some(s) => s,
            None => return Ok(ContType::Cont(self.tid, None)),
        };

        if !is_sendmsg {
            if !self.after_syscall {
                self.after_syscall = true;
                return Ok(ContType::Syscall(self.tid, None));
            }
            self.after_syscall = false;
            self.log("recvmsg");
        } else {
            self.log("sendmsg");
        }

        let msghdr_size = std::mem::size_of::<libc::msghdr>();
        let mut msghdr: libc::msghdr = unsafe { std::mem::zeroed() };
        let msghdr_u8_arr = unsafe {
            std::slice::from_raw_parts_mut(
                (&mut msghdr as *mut libc::msghdr) as *mut u8,
                msghdr_size,
            )
        };
        let msghdr_ioslice = IoSliceMut::new(msghdr_u8_arr);
        let msghdr_remote = RemoteIoVec {
            base: regs.rsi as usize,
            len: msghdr_size,
        };

        crate::ctx!(
            process_vm_readv(self.tid, &mut [msghdr_ioslice], &[msghdr_remote],),
            "process_vm_readv for msghdr failed"
        )?;

        let mut bufs: Vec<Vec<u8>> = Vec::with_capacity(msghdr.msg_iovlen as usize);
        let mut remotes: Vec<RemoteIoVec> = Vec::with_capacity(msghdr.msg_iovlen as usize);
        unsafe {
            let mut iovs: Vec<libc::iovec> = vec![std::mem::zeroed(); msghdr.msg_iovlen as usize];
            let iovs_u8 = iovs
                .iter_mut()
                .map(|iov| {
                    std::slice::from_raw_parts_mut(
                        (iov as *mut libc::iovec) as *mut u8,
                        std::mem::size_of::<libc::iovec>(),
                    )
                })
                .collect::<Vec<_>>();
            let mut iovs_ioslice = iovs_u8
                .into_iter()
                .map(|iov| IoSliceMut::new(iov))
                .collect::<Vec<_>>();
            let iovs_remote = (0..msghdr.msg_iovlen as usize)
                .map(|i| RemoteIoVec {
                    base: msghdr.msg_iov as usize + i * std::mem::size_of::<libc::iovec>(),
                    len: std::mem::size_of::<libc::iovec>(),
                })
                .collect::<Vec<_>>();

            crate::ctx!(
                process_vm_readv(self.tid, &mut iovs_ioslice, &iovs_remote,),
                "process_vm_readv for msg_iov array failed"
            )?;

            for iov in iovs {
                let buf = vec![0 as u8; iov.iov_len];
                let remote = RemoteIoVec {
                    base: iov.iov_base as usize,
                    len: iov.iov_len as usize,
                };
                remotes.push(remote);
                bufs.push(buf);
            }
        }

        let mut bufs_ioslice = bufs
            .iter_mut()
            .map(|x| IoSliceMut::new(x))
            .collect::<Vec<_>>();

        crate::ctx!(
            process_vm_readv(self.tid, &mut bufs_ioslice, &remotes,),
            "process_vm_readv for buf failed"
        )?;

        write_sock(
            &get_oncelock(&CONF)?.outdir,
            sock.fd,
            &sock.name,
            !is_sendmsg,
            &bufs.concat(),
        )?;
        Ok(ContType::Cont(self.tid, None))
    }

    fn intercept_sendto_recvfrom_write_read(
        &mut self,
        regs: libc::user_regs_struct,
        is_sendto: bool,
    ) -> Result<ContType> {
        let sock = match self.get_sock(regs)? {
            Some(s) => s,
            None => return Ok(ContType::Cont(self.tid, None)),
        };

        if !is_sendto {
            if !self.after_syscall {
                self.after_syscall = true;
                return Ok(ContType::Syscall(self.tid, None));
            }
            self.after_syscall = false;
            self.log("recvfrom|read");
        } else {
            self.log("sendmsg");
        }

        let mut buf = vec![0 as u8; regs.rdx as usize];
        let buf_remote = RemoteIoVec {
            base: regs.rsi as usize,
            len: regs.rdx as usize,
        };

        let buf_ioslice = IoSliceMut::new(&mut buf);

        crate::ctx!(
            process_vm_readv(self.tid, &mut [buf_ioslice], &[buf_remote]),
            "process_vm_readv for buf failed"
        )?;

        write_sock(
            &get_oncelock(&CONF)?.outdir,
            sock.fd,
            &sock.name,
            !is_sendto,
            &buf,
        )?;
        Ok(ContType::Cont(self.tid, None))
    }

    fn get_sock(&self, regs: libc::user_regs_struct) -> Result<Option<Socket>> {
        let fd = regs.rdi as i32;
        let track_fds_read = read_rwlock(&self.fd_map)?;
        Ok(track_fds_read.get(&fd).map(|x| x.clone()))
    }

    fn read_unix_path(&self, sockaddr_ptr: usize) -> Result<String> {
        let mut sockaddr_u8_arr: [u8; 108] = [0 as u8; 108];
        let sockaddr_ioslice = IoSliceMut::new(&mut sockaddr_u8_arr);
        let sockaddr_rem = RemoteIoVec {
            base: sockaddr_ptr + 2,
            len: 108,
        };
        crate::ctx!(
            process_vm_readv(self.tid, &mut [sockaddr_ioslice], &[sockaddr_rem]),
            "process_vm_readv failed to read unix socket path"
        )?;

        let end = sockaddr_u8_arr
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(sockaddr_u8_arr.len());
        Ok(String::from_utf8_lossy(&sockaddr_u8_arr[..end]).to_string())
    }

    fn is_unix_family(&self, regs: &libc::user_regs_struct) -> Result<bool> {
        let mut family_u8_arr: [u8; 2] = [0 as u8; 2];
        let family_ioslice = IoSliceMut::new(&mut family_u8_arr);
        let family_rem = RemoteIoVec {
            base: regs.rsi as usize,
            len: 4,
        };

        crate::ctx!(
            process_vm_readv(self.tid, &mut [family_ioslice], &[family_rem]),
            "process_vm_readv failed to read socket family"
        )?;

        let family = i16::from_ne_bytes(family_u8_arr);

        Ok(family as i32 == libc::AF_UNIX)
    }

    fn check_new_fd(&mut self, regs: libc::user_regs_struct) -> Result<ContType> {
        if !self.is_unix_family(&regs)? {
            return Ok(ContType::Cont(self.tid, None));
        }

        let sockaddr = self.read_unix_path(regs.rsi as usize)?;
        let target_sock = &get_oncelock(&CONF)?.sock;
        if target_sock.as_ref().is_none_or(|s| &sockaddr == s) {
            let fd = regs.rdi as i32;
            let socket = Socket {
                fd: fd,
                name: Arc::new(sockaddr),
            };

            let mut track_fds_write = write_rwlock(&self.fd_map)?;
            track_fds_write.insert(fd, socket);
            self.log("New fd");
        }
        Ok(ContType::Cont(self.tid, None))
    }

    pub fn handle_syscall(&mut self) -> Result<ContType> {
        let regs = ptrace::getregs(self.tid)?;
        match regs.orig_rax as i64 {
            libc::SYS_bind | libc::SYS_connect => self.check_new_fd(regs),
            libc::SYS_sendto | libc::SYS_write => {
                self.intercept_sendto_recvfrom_write_read(regs, true)
            }
            libc::SYS_recvfrom | libc::SYS_read => {
                self.intercept_sendto_recvfrom_write_read(regs, false)
            }
            libc::SYS_sendmsg => self.intercept_sendmsg_recvmsg(regs, true),
            libc::SYS_recvmsg => self.intercept_sendmsg_recvmsg(regs, false),
            _ => {
                self.log(&format!("Unregistered syscall: {}", regs.orig_rax));
                Ok(ContType::Cont(self.tid, None))
            }
        }
    }

    fn new_process(&self) -> Result<ContType> {
        let newtid = unistd::Pid::from_raw(ptrace::getevent(self.tid)? as i32);
        self.log(&format!("FORK|VFORK: new process {}", newtid));

        let new_fd_map_bare = read_rwlock(self.fd_map.as_ref())?.clone();
        let new_fd_map = Arc::new(RwLock::new(new_fd_map_bare));

        let t = Tracer::new(newtid, newtid, Some(new_fd_map))?;
        get_oncelock(&NEW_TRACERS)?
            .lock()
            .map_err(|e| anyhow!("Mutex poisoned: {e}"))?
            .push(t);
        Ok(ContType::Cont(self.tid, None))
    }

    fn new_thread(&self) -> Result<ContType> {
        let newtid = unistd::Pid::from_raw(ptrace::getevent(self.tid)? as i32);
        self.log(&format!("CLONE: new thread {}", newtid));
        let t = Tracer::new(newtid, self.tgid, Some(self.fd_map.clone()))?;
        get_oncelock(&NEW_TRACERS)?
            .lock()
            .map_err(|e| anyhow!("Mutex poisoned: {e}"))?
            .push(t);
        Ok(ContType::Cont(self.tid, None))
    }

    fn rebuild_fd_map(&mut self) -> Result<ContType> {
        self.log("EXEC: rebuilding fd map");
        self.fd_map = {
            let fd_map_read = read_rwlock(&self.fd_map)?;
            let proc_path = format!("/proc/{}/fd", self.tgid);
            let mut inherited_fds: Vec<i32> = Vec::new();

            for fd_file in std::fs::read_dir(proc_path)? {
                let fd_file = fd_file?;
                let fd_filename = fd_file.file_name().into_string().unwrap();
                let fd = i32::from_str_radix(&fd_filename, 10)?;
                inherited_fds.push(fd);
            }

            Arc::new(RwLock::new(
                inherited_fds
                    .iter()
                    .filter_map(|k| fd_map_read.get(k).map(|v| (*k, v.clone())))
                    .collect::<HashMap<i32, Socket>>(),
            ))
        };

        Ok(ContType::Cont(self.tid, None))
    }

    fn handle_ev(&mut self, ev: i32) -> Result<ContType> {
        match ev {
            SECCOMP_EVENT => self.handle_syscall(),
            CLONE_EVENT => self.new_thread(),
            FORK_EVENT | VFORK_EVENT => self.new_process(),
            EXEC_EVENT => self.rebuild_fd_map(),
            _ => Ok(ContType::Cont(self.tid, None)),
        }
    }
}

fn trace(primary_t: Tracer) -> Result<()> {
    crate::ctx!(
        ptrace::seize(
            primary_t.tid,
            Options::PTRACE_O_TRACESYSGOOD
                | Options::PTRACE_O_TRACESECCOMP
                | Options::PTRACE_O_TRACECLONE
                | Options::PTRACE_O_TRACEFORK
                | Options::PTRACE_O_TRACEVFORK
                | Options::PTRACE_O_TRACEEXEC,
        ),
        "ptrace::seize failed to attach to {}",
        primary_t.tid
    )?;
    primary_t.log("Tracer attached");
    ptrace::cont(primary_t.tid, None)?;

    let mut tracers = write_rwlock(get_oncelock(&TRACERS)?)?;
    tracers.insert(primary_t.tid, primary_t);
    loop {
        let cont_type = match waitpid(unistd::Pid::from_raw(-1), None)? {
            WaitStatus::Signaled(tid, sig, _) => ContType::Cont(tid, Some(sig)),
            WaitStatus::PtraceEvent(tid, _, ev) => {
                let t = tracers
                    .get_mut(&tid)
                    .expect(&format!("Tracer's TID is not registered {}", tid));

                t.handle_ev(ev)?
            }
            WaitStatus::PtraceSyscall(tid) => {
                let t = tracers
                    .get_mut(&tid)
                    .expect(&format!("Tracer's TID is not registered {}", tid));

                t.handle_syscall()?
            }
            WaitStatus::Stopped(tid, _) | WaitStatus::Continued(tid) => ContType::Cont(tid, None),

            WaitStatus::StillAlive | WaitStatus::Exited(_, _) => ContType::Exit,
        };

        {
            let new_tracers = {
                let mut l = get_oncelock(&NEW_TRACERS)?
                    .lock()
                    .map_err(|e| anyhow!("Mutex poisoned: {e}"))?;
                std::mem::take(&mut *l)
            };

            tracers.extend(new_tracers.into_iter().map(|t| (t.tid, t)));
        }

        match cont_type {
            ContType::Syscall(tid, sig) => {
                ptrace::syscall(tid, sig)?;
            }
            ContType::Exit => {}
            ContType::Cont(tid, sig) => {
                ptrace::cont(tid, sig)?;
            }
        }
    }
}

pub fn tracer_procedure(sock: Option<String>, outdir: PathBuf) -> Result<()> {
    let tracee_pid = unistd::getppid();

    CONF.get_or_init(|| Conf { sock, outdir });
    NEW_TRACERS.get_or_init(|| Mutex::new(Vec::new()));
    TRACERS.get_or_init(|| RwLock::new(HashMap::new()));

    let tracer = Tracer::new(tracee_pid, tracee_pid, None)?;
    if let Err(e) = trace(tracer) {
        eprintln!("{}", e)
    }

    Ok(())
}
