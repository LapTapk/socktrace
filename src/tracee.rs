use anyhow::Result;
use libseccomp::{ScmpAction, ScmpFilterContext, ScmpSyscall};
use nix::sys::signal;
use nix::unistd;
use std::ffi::CString;

macro_rules! add_rules {
    ($filter:expr => $( $syscall:expr $(,)? )* ) => {
       $(
            $filter.add_rule(ScmpAction::Trace(0), ScmpSyscall::from_name($syscall)?)?;
       )*
    }
}

fn install_filter() -> Result<()> {
    let mut filter = ScmpFilterContext::new(ScmpAction::Allow)?;

    add_rules!(filter =>
        "sendmsg",
        "recvmsg",
        "sendto",
        "recvfrom",
        "send",
        "recv",
        "read",
        "write",
        "readv",
        "writev",
        "sendfile",
        "splice",
        "vmsplice",
        "tee",
        "copy_file_range",
        "bind",
        "connect",
        "close"
    );

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

    signal::raise(signal::Signal::SIGSTOP)?;
    match unistd::execv(&c_target[0], &c_target) {
        Ok(_) => unreachable!(),
        Err(e) => Err(e.into()),
    }
}
