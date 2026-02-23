mod log;
mod output;
mod tracee;
mod tracer;

use crate::tracee::tracee_procedure;
use crate::tracer::tracer_procedure;
use anyhow::Result;
use clap::Parser;
use nix::unistd;
use std::path::PathBuf;

#[derive(Parser, Debug)]
struct Cli {
    #[arg(env = "SOCKTRACE_OUT")]
    outdir: PathBuf,

    #[arg(env = "SOCKTRACE_TARGET")]
    target: Vec<String>,
    
    #[arg(long, env = "SOCKTRACE_SOCK")]
    sock: Option<String>,
}

fn main() -> Result<()> {
    let args = Cli::parse();

    match unsafe { unistd::fork() } {
        Ok(unistd::ForkResult::Parent { child: _ }) => {
            let res = tracee_procedure(args.target);
            if let Err(e) = &res {
                crate::log_err!(e);
            }
            res
        }
        Ok(unistd::ForkResult::Child) => {
            let res = tracer_procedure(args.sock, args.outdir);
            if let Err(e) = &res {
                crate::log_err!(e);
            }
            res
        }
        Err(e) => {
            log_err!(e);
            Err(e.into())
        }
    }
}
