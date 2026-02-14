mod log;

use clap::Parser;
use anyhow::Result;
use libseccomp::{ScmpAction, ScmpFilterContext, ScmpSyscall};

#[derive(Parser, Debug)]
struct Cli {
    #[arg(env = "SOCKTRACE_SOCK")]
    sock: Option<String>,

    #[arg(env = "SOCKTRACE_TARGET")]
    target: Vec<String>,
}

fn install_filter() -> Result<()> {
    let mut filter = ScmpFilterContext::new(ScmpAction::Allow)?;

    filter.add_rule(ScmpAction::Trace(0), ScmpSyscall::from_name("sendmsg")?)?;
    filter.add_rule(ScmpAction::Trace(0), ScmpSyscall::from_name("recvmsg")?)?;

    filter.add_rule(ScmpAction::Trace(0), ScmpSyscall::from_name("sendto")?)?;
    filter.add_rule(ScmpAction::Trace(0), ScmpSyscall::from_name("recvfrom")?)?;

    filter.add_rule(ScmpAction::Trace(0), ScmpSyscall::from_name("send")?)?;
    filter.add_rule(ScmpAction::Trace(0), ScmpSyscall::from_name("recv")?)?;

    filter.add_rule(ScmpAction::Trace(0), ScmpSyscall::from_name("read")?)?;
    filter.add_rule(ScmpAction::Trace(0), ScmpSyscall::from_name("write")?)?;

    filter.add_rule(ScmpAction::Trace(0), ScmpSyscall::from_name("readv")?)?;
    filter.add_rule(ScmpAction::Trace(0), ScmpSyscall::from_name("writev")?)?;
    filter.add_rule(ScmpAction::Trace(0), ScmpSyscall::from_name("preadv")?)?;
    filter.add_rule(ScmpAction::Trace(0), ScmpSyscall::from_name("pwritev")?)?;
    filter.add_rule(ScmpAction::Trace(0), ScmpSyscall::from_name("preadv")?)?;
    filter.add_rule(ScmpAction::Trace(0), ScmpSyscall::from_name("preadv2")?)?;
    filter.add_rule(ScmpAction::Trace(0), ScmpSyscall::from_name("pwritev2")?)?;

    filter.add_rule(ScmpAction::Trace(0), ScmpSyscall::from_name("sendfile")?)?;
    filter.add_rule(ScmpAction::Trace(0), ScmpSyscall::from_name("splice")?)?;
    filter.add_rule(ScmpAction::Trace(0), ScmpSyscall::from_name("vmsplice")?)?;
    filter.add_rule(ScmpAction::Trace(0), ScmpSyscall::from_name("tee")?)?;
    filter.add_rule(ScmpAction::Trace(0), ScmpSyscall::from_name("copy_file_range")?)?;

    filter.add_rule(ScmpAction::Trace(0), ScmpSyscall::from_name("bind")?)?;
    filter.add_rule(ScmpAction::Trace(0), ScmpSyscall::from_name("connect")?)?;

    filter.add_rule(ScmpAction::Trace(0), ScmpSyscall::from_name("dup")?)?;
    filter.add_rule(ScmpAction::Trace(0), ScmpSyscall::from_name("dup2")?)?;
    filter.add_rule(ScmpAction::Trace(0), ScmpSyscall::from_name("dup3")?)?;


    filter.load()?;
    Ok(())
}

fn main() -> Result<()> {
    let args = Cli::parse();
    Ok(())
}
