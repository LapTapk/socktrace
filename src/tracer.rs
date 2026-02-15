use anyhow::Result;
use nix::sys::ptrace;
use nix::sys::ptrace::Options;
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd;
use std::sync::OnceLock;
use tokio::{sync::mpsc, task::JoinHandle, task::JoinSet};

static TX: OnceLock<mpsc::UnboundedSender<unistd::Pid>> = OnceLock::new();
static SOCK: OnceLock<Option<String>> = OnceLock::new();

struct Tracer {
    pid: unistd::Pid,
}

impl Tracer {
    pub fn new(pid: unistd::Pid) -> Self {
        Self { pid }
    }

    fn handle_ev(&self, ev: i32) -> Result<()> {
        Ok(())
    }

    fn _trace(&self) -> Result<()> {
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

    pub fn trace(&self) {
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
pub async fn tracer_procedure(sock: Option<String>) -> Result<()> {
    /*
     * TODO
     * seize with ptrace
     * options: tracesysgood fork vfork clone seccomp exec
     *
     * waitpid
     * dispatch based on the result of waitpid
     * if ptrace event => do smth
     * otherwise => continue
     */
    SOCK.get_or_init(move || sock);

    let tracee_pid = unistd::getppid();
    init_sup(tracee_pid).await?;
    Ok(())
}
