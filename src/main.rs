mod log;
mod tracee;
mod tracer;

use crate::tracee::tracee_procedure;
use crate::tracer::tracer_procedure;
use anyhow::Result;
use clap::Parser;
use nix::unistd;

#[derive(Parser, Debug)]
struct Cli {
    #[arg(env = "SOCKTRACE_SOCK")]
    sock: Option<String>,

    #[arg(env = "SOCKTRACE_TARGET")]
    target: Vec<String>,
}

fn main() -> Result<()> {
    let args = Cli::parse();

    match unsafe { unistd::fork() } {
        Ok(unistd::ForkResult::Parent { child: _ }) => tracee_procedure(args.target),
        Ok(unistd::ForkResult::Child) => tracer_procedure(args.sock),
        Err(e) => {
            log_err!(e);
            Err(e.into())
        }
    }
}
