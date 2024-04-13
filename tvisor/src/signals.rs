#![allow(dead_code)]

use crate::sys::*;
use crate::{guest, println_stdout, rt};
use alloc::string::{String, ToString};

extern "C" fn syscall_handler(_sig: i32, info: &siginfo_t, ucontext: &mut ucontext_t) {
    // Check if the signal is SIGSYS and this is caused by SECCOMP_RET_TRAP.
    assert_eq!(
        info.si_signo, SIGSYS as i32,
        "tvisor sig handler must be called only for SIGSYS"
    );

    const SYS_SECCOMP: i32 = 1;
    if info.si_code != SYS_SECCOMP {
        todo!("non seccomp SIGSYS is not supported yet. we should simply abort?")
    }
    guest::handle_syscall(info, ucontext);
}

extern "C" fn non_syscall_handler(sig: i32, info: &siginfo_t, ucontext: &mut ucontext_t) {
    guest::handle_non_syscall_signal(sig as usize, info, ucontext);
}

pub fn init() {
    const SS_FLAG: i32 = SA_ONSTACK | SA_RESTART | SA_SIGINFO;
    // Allow making syscalls during signal handling.
    const BLOCK_MASK: u64 = !(1 << (SIGSYS - 1) as u64);
    for i in 1..=64 {
        match i {
            // We need to handle SIGSYS differently for seccomp, possibly for delegating to the kernel.
            SIGSYS => sigaction(SIGSYS, syscall_handler, SS_FLAG, !0),
            // These are not allowed to be caught or ignored.
            SIGKILL | SIGSTOP => {}
            _ => {
                sigaction(i, non_syscall_handler, SS_FLAG, BLOCK_MASK);
            }
        }
    }
}

pub fn block_all_signals() {
    sigprocmask(SIG_BLOCK, !0 as SigSet);
}

pub fn unblock_all_signals() {
    sigprocmask(SIG_SETMASK, 0 as SigSet);
}

#[repr(C)]
#[derive(Debug)]
pub struct SigData {
    pub info: *const siginfo_t,
    pub ucontext: *mut ucontext_t,
    pub clone_caller_thread_local: usize,
    pub clone_caller_sigmask: SigSet,
}

impl SigData {
    pub fn set(
        &mut self,
        info: *const siginfo_t,
        ucontext: *mut ucontext_t,
        clone_caller_thread_local: usize,
    ) {
        self.info = info;
        self.ucontext = ucontext;
        self.clone_caller_thread_local = clone_caller_thread_local;
    }

    pub fn info(&self) -> &siginfo_t {
        unsafe { &*self.info }
    }

    #[allow(clippy::mut_from_ref)]
    pub fn ucontext(&self) -> &mut ucontext_t {
        unsafe { &mut *self.ucontext }
    }
}

impl Default for SigData {
    fn default() -> Self {
        Self {
            info: core::ptr::null_mut::<siginfo_t>(),
            ucontext: core::ptr::null_mut::<ucontext_t>(),
            clone_caller_thread_local: 0,
            clone_caller_sigmask: 0,
        }
    }
}

pub const SIGHUP: usize = 0x1;
pub const SIGINT: usize = 0x2;
pub const SIGQUIT: usize = 0x3;
pub const SIGILL: usize = 0x4;
pub const SIGTRAP: usize = 0x5;
pub const SIGABRT: usize = 0x6;
pub const SIGBUS: usize = 0x7;
pub const SIGFPE: usize = 0x8;
pub const SIGKILL: usize = 0x9;
pub const SIGUSR1: usize = 0xa;
pub const SIGSEGV: usize = 0xb;
pub const SIGUSR2: usize = 0xc;
pub const SIGPIPE: usize = 0xd;
pub const SIGALRM: usize = 0xe;
pub const SIGTERM: usize = 0xf;
pub const SIGSTKFLT: usize = 0x10;
pub const SIGCHLD: usize = 0x11;
pub const SIGCONT: usize = 0x12;
pub const SIGSTOP: usize = 0x13;
pub const SIGTSTP: usize = 0x14;
pub const SIGTTIN: usize = 0x15;
pub const SIGTTOU: usize = 0x16;
pub const SIGURG: usize = 0x17;
pub const SIGXCPU: usize = 0x18;
pub const SIGXFSZ: usize = 0x19;
pub const SIGVTALRM: usize = 0x1a;
pub const SIGPROF: usize = 0x1b;
pub const SIGWINCH: usize = 0x1c;
pub const SIGIO: usize = 0x1d;
pub const SIGPWR: usize = 0x1e;
pub const SIGSYS: usize = 0x1f;
pub const SIGRTMN: usize = 0x20;

pub type SigSet = u64;

pub fn sigaddset(set: &mut SigSet, signal: usize) {
    *set |= 1 << (signal - 1);
}

pub fn sigdelset(set: &mut SigSet, signal: usize) {
    *set &= !(1 << (signal - 1));
}

pub fn sigismember(set: &SigSet, signal: usize) -> bool {
    *set & (1 << (signal - 1)) != 0
}

pub fn synchronous_signal(sig: usize) -> bool {
    matches!(sig, SIGILL | SIGFPE | SIGSEGV | SIGBUS | SIGTRAP | SIGSYS)
}

pub fn sig_to_string(sig: usize) -> &'static str {
    match sig {
        SIGHUP => "SIGHUP",
        SIGINT => "SIGINT",
        SIGQUIT => "SIGQUIT",
        SIGILL => "SIGILL",
        SIGTRAP => "SIGTRAP",
        SIGABRT => "SIGABRT",
        SIGBUS => "SIGBUS",
        SIGFPE => "SIGFPE",
        SIGKILL => "SIGKILL",
        SIGUSR1 => "SIGUSR1",
        SIGSEGV => "SIGSEGV",
        SIGUSR2 => "SIGUSR2",
        SIGPIPE => "SIGPIPE",
        SIGALRM => "SIGALRM",
        SIGTERM => "SIGTERM",
        SIGSTKFLT => "SIGSTKFLT",
        SIGCHLD => "SIGCHLD",
        SIGCONT => "SIGCONT",
        SIGSTOP => "SIGSTOP",
        SIGTSTP => "SIGTSTP",
        SIGTTIN => "SIGTTIN",
        SIGTTOU => "SIGTTOU",
        SIGURG => "SIGURG",
        SIGXCPU => "SIGXCPU",
        SIGXFSZ => "SIGXFSZ",
        SIGVTALRM => "SIGVTALRM",
        SIGPROF => "SIGPROF",
        SIGWINCH => "SIGWINCH",
        SIGIO => "SIGIO",
        SIGPWR => "SIGPWR",
        SIGSYS => "SIGSYS",
        SIGRTMN => "SIGRTMN",
        _ => "UNKNOWN",
    }
}

pub fn sigmask_to_string(mask: SigSet) -> String {
    if mask == 0 {
        return "empty".to_string();
    }
    let mut s = String::new();
    for i in 1..=64usize.min(SIGRTMN) {
        if sigismember(&mask, i) {
            s.push_str(sig_to_string(i));
            s.push('|');
        }
    }
    s.pop();
    s
}

pub fn sig_abort(sig: usize) {
    match sig {
        SIGILL => {
            println_stdout!("Illegal instruction");
        }
        SIGSEGV => {
            println_stdout!("Segmentation fault");
        }
        SIGBUS => {
            println_stdout!("Bus error");
        }
        _ => {
            println_stdout!("aborting with {} ", sig_to_string(sig));
        }
    }
    rt::abort(128 + sig as i32)
}

pub fn do_default_sigaction(sig: usize) {
    // https://man7.org/linux/man-pages/man7/signal.7.html.
    match sig {
        SIGHUP => sig_abort(SIGHUP),             // Term
        SIGINT => sig_abort(SIGINT),             // Term
        SIGQUIT => sig_abort(SIGQUIT),           // Core
        SIGILL => sig_abort(SIGILL),             // Core
        SIGABRT => sig_abort(SIGABRT),           // Core
        SIGFPE => sig_abort(SIGFPE),             // Core
        SIGKILL => sig_abort(SIGKILL), // Term // but see ThreadGroup.applySignalSideEffects
        SIGSEGV => sig_abort(SIGSEGV), // Core
        SIGPIPE => sig_abort(SIGPIPE), // Term
        SIGALRM => sig_abort(SIGALRM), // Term
        SIGTERM => sig_abort(SIGTERM), // Term
        SIGUSR1 => sig_abort(SIGUSR1), // Term
        SIGUSR2 => sig_abort(SIGUSR2), // Term
        SIGCHLD => {}                  // Ignore
        SIGCONT => {}                  // Ignore
        SIGSTOP => todo!("Stop default action"), // Stop,
        SIGTSTP => todo!("Stop default action"), // Stop,
        SIGTTIN => todo!("Stop default action"), // Stop,
        SIGTTOU => todo!("Stop default action"), // Stop,
        SIGBUS => sig_abort(SIGBUS),   // Core
        SIGPROF => sig_abort(SIGPROF), // Term
        SIGSYS => sig_abort(SIGSYS),   // Core
        SIGTRAP => sig_abort(SIGTRAP), // Core
        SIGURG => {}                   // Ignore
        SIGVTALRM => sig_abort(SIGVTALRM), // Term
        SIGXCPU => sig_abort(SIGXCPU), // Core
        SIGXFSZ => sig_abort(SIGXFSZ), // Core
        SIGSTKFLT => sig_abort(SIGSTKFLT), // Term
        SIGIO => sig_abort(SIGIO),     // Term
        SIGPWR => sig_abort(SIGPWR),   // Term
        SIGWINCH => {}                 // Ignore
        _ => todo!("default action for signal {}", sig_to_string(sig)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_case;

    test_case!(test_synchronous_signal, {
        assert!(synchronous_signal(SIGILL));
        assert!(synchronous_signal(SIGFPE));
        assert!(synchronous_signal(SIGSEGV));
        assert!(synchronous_signal(SIGBUS));
        assert!(synchronous_signal(SIGTRAP));
        assert!(synchronous_signal(SIGSYS));
        assert!(!synchronous_signal(SIGHUP));
        assert!(!synchronous_signal(SIGINT));
        assert!(!synchronous_signal(SIGQUIT));
        assert!(!synchronous_signal(SIGABRT));
        assert!(!synchronous_signal(SIGKILL));
        assert!(!synchronous_signal(SIGUSR1));
        assert!(!synchronous_signal(SIGUSR2));
        assert!(!synchronous_signal(SIGPIPE));
        assert!(!synchronous_signal(SIGALRM));
        assert!(!synchronous_signal(SIGSTKFLT));
        assert!(!synchronous_signal(SIGCHLD));
        assert!(!synchronous_signal(SIGCONT));
        assert!(!synchronous_signal(SIGSTOP));
        assert!(!synchronous_signal(SIGTSTP));
        assert!(!synchronous_signal(SIGTTIN));
        assert!(!synchronous_signal(SIGTTOU));
        assert!(!synchronous_signal(SIGURG));
        assert!(!synchronous_signal(SIGXCPU));
        assert!(!synchronous_signal(SIGXFSZ));
        assert!(!synchronous_signal(SIGVTALRM));
        assert!(!synchronous_signal(SIGPROF));
        assert!(!synchronous_signal(SIGWINCH));
        assert!(!synchronous_signal(SIGIO));
        assert!(!synchronous_signal(SIGPWR));
        assert!(!synchronous_signal(SIGRTMN));
    });

    test_case!(test_sigaddset, {
        let mut set: SigSet = 0;
        sigaddset(&mut set, 1);
        assert_eq!(set, 1);
        sigaddset(&mut set, 2);
        assert_eq!(set, 3);
        sigaddset(&mut set, 3);
        assert_eq!(set, 7);
    });

    test_case!(test_sigismember, {
        let mut set: SigSet = 0;
        sigaddset(&mut set, 1);
        assert_eq!(sigismember(&set, 1), true);
        assert_eq!(sigismember(&set, 2), false);
        sigaddset(&mut set, 2);
        assert_eq!(sigismember(&set, 1), true);
        assert_eq!(sigismember(&set, 2), true);
        assert_eq!(sigismember(&set, 3), false);
    });

    test_case!(test_sigdelset, {
        let mut set: SigSet = 0;
        sigaddset(&mut set, 1);
        sigaddset(&mut set, 2);
        sigaddset(&mut set, 3);
        sigdelset(&mut set, 2);
        assert!(!sigismember(&set, 2));
        assert!(sigismember(&set, 1));
        assert!(sigismember(&set, 3));

        sigdelset(&mut set, 1);
        assert!(!sigismember(&set, 1));
        assert!(sigismember(&set, 3));
    });
}
