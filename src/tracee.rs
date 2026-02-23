use anyhow::Result;
use nix::sys::signal;
use nix::unistd;
use std::ffi::CString;
use std::io;

#[repr(C)]
#[derive(Clone, Copy)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

const fn stmt(code: u16, k: u32) -> SockFilter {
    SockFilter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}
const fn jeq(k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter {
        code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
        jt,
        jf,
        k,
    }
}

fn seccomp_load(prog: &SockFprog) -> io::Result<()> {
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_TSYNC,
            prog as *const _ as *const i64,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn build_trace_prog(syscalls: &[u32]) -> Vec<SockFilter> {
    const SECCOMP_DATA_NR_OFFSET: u32 = 0;

    let mut p = Vec::with_capacity(2 + syscalls.len() * 2 + 1);

    p.push(stmt(
        (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
        SECCOMP_DATA_NR_OFFSET,
    ));

    for &nr in syscalls {
        p.push(jeq(nr, 0, 1));
        p.push(stmt(libc::BPF_RET as u16, libc::SECCOMP_RET_TRACE));
    }

    p.push(stmt(libc::BPF_RET as u16, libc::SECCOMP_RET_ALLOW));
    p
}

fn install_filter() -> Result<()> {
    let syscalls: [u32; 16] = [
        libc::SYS_sendmsg as u32,
        libc::SYS_recvmsg as u32,
        libc::SYS_sendto as u32,
        libc::SYS_recvfrom as u32,
        libc::SYS_read as u32,
        libc::SYS_write as u32,
        libc::SYS_readv as u32,
        libc::SYS_writev as u32,
        libc::SYS_sendfile as u32,
        libc::SYS_splice as u32,
        libc::SYS_vmsplice as u32,
        libc::SYS_tee as u32,
        libc::SYS_copy_file_range as u32,
        libc::SYS_bind as u32,
        libc::SYS_connect as u32,
        libc::SYS_close as u32,
    ];

    let list = syscalls.to_vec();
    let prog_insns = build_trace_prog(&list);

    let prog = SockFprog {
        len: prog_insns.len() as u16,
        filter: prog_insns.as_ptr(),
    };

    seccomp_load(&prog)?;

    Ok(())
}

pub fn tracee_procedure(target: Vec<String>) -> Result<()> {
    unsafe {
        libc::prctl(libc::PR_SET_PTRACER, libc::PR_SET_PTRACER_ANY);
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
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
