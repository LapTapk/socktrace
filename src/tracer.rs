use crate::output::write_sock;
use anyhow::{Result, anyhow};
use nix::sys::ptrace;
use nix::sys::ptrace::Options;
use nix::sys::signal::Signal;
use nix::sys::uio::{RemoteIoVec, process_vm_readv};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd;
use std::collections::HashMap;
use std::ffi::CStr;
use std::io::IoSliceMut;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock, RwLock, RwLockReadGuard, RwLockWriteGuard};
use tokio::{sync::mpsc, task::JoinSet};

type NewTracerConf = (unistd::Pid, unistd::Pid);

struct Conf {
    tx: mpsc::UnboundedSender<NewTracerConf>,
    sock: Option<String>,
    outdir: PathBuf,
    fd_maps: RwLock<HashMap<unistd::Pid, PerProcFdMap>>,
}

static CONF: OnceLock<Conf> = OnceLock::new();

const SECCOMP_EVENT: i32 =
    Signal::SIGTRAP as i32 | ((ptrace::Event::PTRACE_EVENT_SECCOMP as i32) << 8);
const CLONE_EVENT: i32 = Signal::SIGTRAP as i32 | ((ptrace::Event::PTRACE_EVENT_CLONE as i32) << 8);
const FORK_EVENT: i32 = Signal::SIGTRAP as i32 | ((ptrace::Event::PTRACE_EVENT_FORK as i32) << 8);
const VFORK_EVENT: i32 = Signal::SIGTRAP as i32 | ((ptrace::Event::PTRACE_EVENT_VFORK as i32) << 8);
const EXEC_EVENT: i32 = Signal::SIGTRAP as i32 | ((ptrace::Event::PTRACE_EVENT_EXEC as i32) << 8);

struct Socket {
    fd: i32,
    name: String,
}

type PerProcFdMap = Arc<RwLock<HashMap<i32, Socket>>>;

fn get_conf() -> Result<&'static Conf> {
    CONF.get().ok_or(anyhow!("CONF is not initialized"))
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
    track_fds: PerProcFdMap,
}

impl Tracer {
    pub fn new(tid: unistd::Pid, tgid: unistd::Pid) -> Result<Self> {
        let mut fd_maps_write = write_rwlock(&get_conf()?.fd_maps)?;
        let fd_map = fd_maps_write
            .entry(tgid)
            .or_insert_with(|| Arc::new(RwLock::new(HashMap::new())));

        Ok(Self {
            tid,
            tgid,
            track_fds: fd_map.clone(),
        })
    }

    fn check_sending_data(&self, regs: libc::user_regs_struct) -> Result<()> {
        let fd = regs.rdi as i32;
        let track_fds_read = read_rwlock(&self.track_fds)?;
        let sock = match track_fds_read.get(&fd) {
            Some(s) => s,
            None => return Ok(()),
        };

        let mut buf = vec![0 as u8; regs.rdx as usize];
        let buf_ioslice = IoSliceMut::new(&mut buf);
        let buf_remote = RemoteIoVec {
            base: regs.rsi as usize,
            len: regs.rdx as usize,
        };
        process_vm_readv(self.tid, &mut [buf_ioslice], &[buf_remote])?;

        write_sock(&get_conf()?.outdir, sock.fd, &sock.name, false, &buf)?;

        Ok(())
    }

    fn read_unix_path(&self, sockaddr_ptr: usize) -> Result<String> {
        let mut sockaddr_u8_arr: [u8; 108] = [0 as u8; 108];
        let sockaddr_ioslice = IoSliceMut::new(&mut sockaddr_u8_arr);
        let sockaddr_rem = RemoteIoVec {
            base: sockaddr_ptr + 4,
            len: 108,
        };
        process_vm_readv(self.tid, &mut [sockaddr_ioslice], &[sockaddr_rem])?;
        let cstr = CStr::from_bytes_with_nul(&sockaddr_u8_arr).unwrap();
        let s = cstr.to_str().unwrap();
        Ok(s.to_string())
    }

    fn is_unix_family(&self, regs: &libc::user_regs_struct) -> Result<bool> {
        let mut family_u8_arr: [u8; 4] = [0 as u8; 4];
        let family_ioslice = IoSliceMut::new(&mut family_u8_arr);
        let family_rem = RemoteIoVec {
            base: regs.rsi as usize,
            len: 4,
        };
        process_vm_readv(self.tid, &mut [family_ioslice], &[family_rem])?;

        let family = i32::from_ne_bytes(family_u8_arr);

        Ok(family == libc::AF_UNIX)
    }

    fn check_new_fd(&mut self, regs: libc::user_regs_struct) -> Result<()> {
        if !self.is_unix_family(&regs)? {
            return Ok(());
        }

        let sockaddr = self.read_unix_path(regs.rsi as usize)?;
        let target_sock = &get_conf()?.sock;
        if target_sock.as_ref().is_none_or(|s| &sockaddr == s) {
            let fd = regs.rdi as i32;
            let socket = Socket {
                fd: fd,
                name: sockaddr,
            };

            let mut track_fds_write = write_rwlock(&self.track_fds)?;
            track_fds_write.insert(fd, socket);
        }
        Ok(())
    }

    fn handle_seccomp(&mut self) -> Result<()> {
        let regs = ptrace::getregs(self.tid)?;
        match regs.rax as i64 {
            libc::SYS_bind | libc::SYS_connect => self.check_new_fd(regs)?,
            libc::SYS_sendto => self.check_sending_data(regs)?,
            _ => return Err(anyhow::Error::msg("Unregistered syscall")),
        }
        Ok(())
    }

    fn new_process(&self) -> Result<()> {
        let newpid = unistd::Pid::from_raw(ptrace::getevent(self.tid)? as i32);
        get_conf()?.tx.send((newpid, newpid))?;
        Ok(())
    }

    fn new_thread(&self) -> Result<()> {
        let newpid = unistd::Pid::from_raw(ptrace::getevent(self.tid)? as i32);
        get_conf()?.tx.send((newpid, self.tgid))?;
        Ok(())
    }

    fn reset(&self) -> Result<()> {
        Ok(())
    }

    fn handle_ev(&mut self, ev: i32) -> Result<()> {
        match ev >> 8 {
            SECCOMP_EVENT => self.handle_seccomp(),
            CLONE_EVENT => self.new_thread(),
            FORK_EVENT | VFORK_EVENT => self.new_process(),
            EXEC_EVENT => self.reset(),
            _ => Ok(()),
        }
    }

    fn _trace(&mut self) -> Result<()> {
        ptrace::seize(
            self.tid,
            Options::PTRACE_O_TRACESYSGOOD
                | Options::PTRACE_O_TRACESECCOMP
                | Options::PTRACE_O_TRACECLONE
                | Options::PTRACE_O_TRACEFORK
                | Options::PTRACE_O_TRACEVFORK
                | Options::PTRACE_O_TRACEEXEC,
        )?;
        loop {
            match waitpid(self.tid, None)? {
                WaitStatus::Signaled(_, sig, _) => {
                    ptrace::cont(self.tid, sig)?;
                }
                WaitStatus::PtraceEvent(_, _, ev) => {
                    self.handle_ev(ev)?;
                }
                _ => ptrace::cont(self.tid, None)?,
            }
        }
    }

    pub fn trace(&mut self) {
        if let Err(e) = self._trace() {
            eprint!("[TID: {} TGID: {}]", self.tid, self.tgid);
            crate::log_err!(e);
        }
    }
}

fn try_spawn_tracer(tid: unistd::Pid, tgid: unistd::Pid) {
    match &mut Tracer::new(tid, tgid) {
        Ok(t) => t.trace(),
        Err(e) => {
            eprint!("[TID: {} TGID: {}] (Tracer's startup failed) ", tid, tgid);
            crate::log_err!(e);
        }
    }
}

async fn supervisor(tid: unistd::Pid, mut rx: mpsc::UnboundedReceiver<NewTracerConf>) {
    let mut joinset: JoinSet<()> = JoinSet::new();
    joinset.spawn_blocking(move || try_spawn_tracer(tid, tid));

    loop {
        tokio::select!(
            Some((newtid, newtgid)) = rx.recv() => {
                joinset.spawn_blocking(move || try_spawn_tracer(newtid, newtgid));
            }
            join_res = joinset.join_next() => {
                if let None = join_res {
                    break;
                }
            }

        );
    }
}

#[tokio::main]
pub async fn tracer_procedure(sock: Option<String>, outdir: PathBuf) -> Result<()> {
    /*
     * TODO
     * handle fork, vfork, clone and exec
     */

    let tracee_pid = unistd::getppid();
    let (tx, rx) = mpsc::unbounded_channel::<NewTracerConf>();

    CONF.get_or_init(|| Conf {
        tx,
        sock,
        outdir,
        fd_maps: RwLock::new(HashMap::new()),
    });
    tokio::spawn(supervisor(tracee_pid, rx)).await?;
    Ok(())
}
