use anyhow::Result;
use libseccomp::{ScmpAction, ScmpFilterContext, ScmpSyscall};
use nix::unistd;
use nix::sys::signal;
use std::ffi::CString;

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
    filter.add_rule(
        ScmpAction::Trace(0),
        ScmpSyscall::from_name("copy_file_range")?,
    )?;

    filter.add_rule(ScmpAction::Trace(0), ScmpSyscall::from_name("bind")?)?;
    filter.add_rule(ScmpAction::Trace(0), ScmpSyscall::from_name("connect")?)?;

    filter.add_rule(ScmpAction::Trace(0), ScmpSyscall::from_name("dup")?)?;
    filter.add_rule(ScmpAction::Trace(0), ScmpSyscall::from_name("dup2")?)?;
    filter.add_rule(ScmpAction::Trace(0), ScmpSyscall::from_name("dup3")?)?;

    filter.load()?;
    Ok(())
}

pub fn tracee_procedure(target: Vec<String>) -> Result<()> {
    unsafe {
        libc::prctl(libc::PR_SET_PTRACER, libc::PR_SET_PTRACER_ANY);
    }

    install_filter()?;

    let mut c_target: Vec<CString> = Vec::with_capacity(target.len());
    for s in target {
        c_target.push(CString::new(s)?);
    }

    signal::raise(signal::Signal::SIGSTOP);
    match unistd::execv(&c_target[0], &c_target) {
        Ok(_) => unreachable!(),
        Err(e) => Err(e.into()),
    }
}
