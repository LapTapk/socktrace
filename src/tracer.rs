use crate::output::write_sock;
use anyhow::Result;
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
use std::sync::OnceLock;
use tokio::{sync::mpsc, task::JoinHandle, task::JoinSet};

static TX: OnceLock<mpsc::UnboundedSender<unistd::Pid>> = OnceLock::new();
static SOCK: OnceLock<Option<String>> = OnceLock::new();
static OUTDIR: OnceLock<PathBuf> = OnceLock::new();

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

struct Tracer {
    pid: unistd::Pid,
    track_fds: HashMap<i32, Socket>,
}

impl Tracer {
    pub fn new(pid: unistd::Pid) -> Self {
        Self {
            pid,
            track_fds: HashMap::new(),
        }
    }

    fn check_sending_data(&self, regs: libc::user_regs_struct) -> Result<()> {
        let fd = regs.rdi as i32;
        let sock = match self.track_fds.get(&fd) {
            Some(s) => s,
            None => return Ok(()),
        };

        let mut buf = vec![0 as u8; regs.rdx as usize];
        let buf_ioslice = IoSliceMut::new(&mut buf);
        let buf_remote = RemoteIoVec {
            base: regs.rsi as usize,
            len: regs.rdx as usize,
        };
        process_vm_readv(self.pid, &mut [buf_ioslice], &[buf_remote])?;

        write_sock(&OUTDIR.get().unwrap(), sock.fd, &sock.name, false, &buf)?;

        Ok(())
    }

    fn read_unix_path(&self, sockaddr_ptr: usize) -> Result<String> {
        let mut sockaddr_u8_arr: [u8; 108] = [0 as u8; 108];
        let sockaddr_ioslice = IoSliceMut::new(&mut sockaddr_u8_arr);
        let sockaddr_rem = RemoteIoVec {
            base: sockaddr_ptr + 4,
            len: 108,
        };
        process_vm_readv(self.pid, &mut [sockaddr_ioslice], &[sockaddr_rem])?;
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
        process_vm_readv(self.pid, &mut [family_ioslice], &[family_rem])?;

        let family = i32::from_ne_bytes(family_u8_arr);

        Ok(family == libc::AF_UNIX)
    }

    fn check_new_fd(&mut self, regs: libc::user_regs_struct) -> Result<()> {
        if !self.is_unix_family(&regs)? {
            return Ok(());
        }

        let sockaddr = self.read_unix_path(regs.rsi as usize)?;
        let target_sock = SOCK.get().unwrap();
        if target_sock.as_ref().is_none_or(|s| &sockaddr == s) {
            let fd = regs.rdi as i32;
            let socket = Socket {
                fd: fd,
                name: sockaddr,
            };
            self.track_fds.insert(fd, socket);
        }
        Ok(())
    }

    fn handle_seccomp(&mut self) -> Result<()> {
        let regs = ptrace::getregs(self.pid)?;
        match regs.rax as i64 {
            libc::SYS_bind | libc::SYS_connect => self.check_new_fd(regs)?,
            libc::SYS_sendto => self.check_sending_data(regs)?,
            _ => return Err(anyhow::Error::msg("Unregistered syscall")),
        }
        Ok(())
    }

    fn new_process(&self) -> Result<()> {
        let newpid = unistd::Pid::from_raw(ptrace::getevent(self.pid)? as i32);
        TX.get().unwrap().send(newpid)?;
        Ok(())
    }

    fn reset(&self) -> Result<()> {
        Ok(())
    }

    fn handle_ev(&mut self, ev: i32) -> Result<()> {
        match ev >> 8 {
            SECCOMP_EVENT => self.handle_seccomp(),
            CLONE_EVENT | FORK_EVENT | VFORK_EVENT => self.new_process(),
            EXEC_EVENT => self.reset(),
            _ => Ok(()),
        }
    }

    fn _trace(&mut self) -> Result<()> {
        ptrace::seize(
            self.pid,
            Options::PTRACE_O_TRACESYSGOOD
                | Options::PTRACE_O_TRACESECCOMP
                | Options::PTRACE_O_TRACECLONE
                | Options::PTRACE_O_TRACEFORK
                | Options::PTRACE_O_TRACEVFORK
                | Options::PTRACE_O_TRACEEXEC,
        )?;
        loop {
            match waitpid(self.pid, None)? {
                WaitStatus::Signaled(_, sig, _) => {
                    ptrace::cont(self.pid, sig)?;
                }
                WaitStatus::PtraceEvent(_, _, ev) => {
                    self.handle_ev(ev)?;
                }
                _ => ptrace::cont(self.pid, None)?,
            }
        }
    }

    pub fn trace(&mut self) {
        if let Err(e) = self._trace() {
            eprint!("[PID: {}]", self.pid);
            crate::log_err!(e);
        }
    }
}

async fn supervisor(pid: unistd::Pid, mut rx: mpsc::UnboundedReceiver<unistd::Pid>) {
    let mut joinset: JoinSet<()> = JoinSet::new();
    joinset.spawn_blocking(move || Tracer::new(pid).trace());

    loop {
        tokio::select!(
            Some(newpid) = rx.recv() => {
                joinset.spawn_blocking(move || Tracer::new(newpid).trace());
            }
            join_res = joinset.join_next() => {
                if let None = join_res {
                    break;
                }
            }

        );
    }
}

fn init_sup(pid: unistd::Pid) -> JoinHandle<()> {
    let (tx, rx) = mpsc::unbounded_channel::<unistd::Pid>();
    TX.get_or_init(|| tx);
    tokio::spawn(supervisor(pid, rx))
}

#[tokio::main]
pub async fn tracer_procedure(sock: Option<String>, outdir: PathBuf) -> Result<()> {
    /*
     * TODO
     * handle fork, vfork, clone and exec
     */
    SOCK.get_or_init(move || sock);
    OUTDIR.get_or_init(move || outdir);

    let tracee_pid = unistd::getppid();
    init_sup(tracee_pid).await?;
    Ok(())
}
