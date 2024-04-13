#![allow(dead_code)]

use crate::signals::SigSet;
use core::arch::asm;
use core::fmt::Debug;
use syscalls::*;

pub const EINVAL: i32 = 22;

pub const PROT_NONE: i32 = 0x0;
pub const PROT_READ: i32 = 0x1;
pub const PROT_WRITE: i32 = 0x2;
pub const PROT_EXEC: i32 = 0x4;
pub const MAP_PRIVATE: i32 = 0x02;
pub const MAP_ANONYMOUS: i32 = 0x20;
pub const MAP_FIXED: i32 = 0x10;

pub fn mmap(addr: usize, len: usize, prot: i32, flags: i32) -> *mut u8 {
    const FD: i32 = -1;
    const OFFSET: i32 = 0;

    unsafe {
        match syscall!(
            Sysno::mmap,
            addr as *mut u8,
            len,
            prot,
            flags,
            FD as u32,
            OFFSET
        ) {
            Ok(result) => result as *mut u8,
            Err(err) => panic!("mmap failed: {}", err),
        }
    }
}

pub fn munmap(addr: *const u8, len: usize) {
    unsafe {
        match syscall!(Sysno::munmap, addr, len) {
            Ok(_) => (),
            Err(err) => panic!("munmap failed: {}", err),
        }
    }
}

pub fn mprotect(addr: *mut u8, len: usize, prot: i32) {
    unsafe {
        match syscall!(Sysno::mprotect, addr, len, prot) {
            Ok(_) => (),
            Err(err) => panic!("mprotect failed: {}", err),
        }
    }
}

pub fn gettid() -> usize {
    unsafe {
        match syscall!(Sysno::gettid) {
            Ok(result) => result,
            Err(err) => panic!("gettid failed: {}", err),
        }
    }
}

pub fn getpid() -> usize {
    unsafe {
        match syscall!(Sysno::getpid) {
            Ok(result) => result,
            Err(err) => panic!("getpid failed: {}", err),
        }
    }
}

#[repr(C)]
#[derive(Clone, PartialEq)]
pub struct stack_t {
    pub ss_sp: *mut u8,
    pub ss_flags: usize,
    pub ss_size: usize,
}

impl stack_t {
    pub fn stack_end(&self) -> *mut u8 {
        unsafe { self.ss_sp.add(self.ss_size) }
    }
}

impl Default for stack_t {
    fn default() -> Self {
        Self {
            ss_sp: core::ptr::null_mut::<u8>(),
            ss_flags: 0,
            ss_size: 0,
        }
    }
}

impl Debug for stack_t {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("stack_t")
            .field("ss_sp", &self.ss_sp)
            .field("ss_flags", &self.ss_flags)
            .field("ss_size", &self.ss_size)
            .finish()
    }
}

pub fn sigaltstack(ss_sp: *mut u8, ss_size: usize) {
    let mut ss = stack_t {
        ss_sp,
        ss_flags: 0,
        ss_size,
    };

    unsafe {
        match syscall!(
            Sysno::sigaltstack,
            &mut ss as *mut stack_t,
            core::ptr::null_mut::<u8>()
        ) {
            Ok(_) => (),
            Err(err) => panic!("sigaltstack failed: {}", err),
        }
    }

    // Sanity check.
    if cfg!(debug_assertions) {
        let mut old_ss = ss;
        old_ss.ss_sp = core::ptr::null_mut::<u8>();
        old_ss.ss_size = 0;
        unsafe {
            syscall!(
                Sysno::sigaltstack,
                core::ptr::null_mut::<stack_t>(),
                &mut old_ss as *mut stack_t
            )
            .expect("sigaltstack failed")
        };
        assert_eq!(old_ss.ss_sp, ss_sp);
        assert_eq!(old_ss.ss_size, ss_size);
    }
}

const SIGINFO_T_PAD_SIZE: usize = 128 - 4 - 4 - 4;

#[repr(C)]
#[derive(Clone, PartialEq)]
pub struct siginfo_t {
    pub si_signo: i32,
    pub si_errno: i32,
    pub si_code: i32,

    pad: [u8; SIGINFO_T_PAD_SIZE],
}

pub const SI_QUEUE: i32 = -5;

impl siginfo_t {
    pub fn get_si_pid(&self) -> usize {
        // Extract the PID from si_pid at the beginning of .pad.
        unsafe { core::ptr::read_unaligned(&self.pad[0] as *const u8 as *const usize) }
    }

    pub fn set_si_pid(&mut self, uid: usize) {
        unsafe {
            core::ptr::write_unaligned(&mut self.pad[0] as *mut u8 as *mut usize, uid);
        }
    }
}

pub const SS_ONSTACK: usize = 1;
pub const SS_DISABLE: usize = 2;

impl Default for siginfo_t {
    fn default() -> Self {
        Self {
            si_signo: 0,
            si_errno: 0,
            si_code: 0,
            pad: [0; SIGINFO_T_PAD_SIZE],
        }
    }
}

impl Debug for siginfo_t {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("siginfo_t")
            .field("si_signo", &self.si_signo)
            .field("si_errno", &self.si_errno)
            .field("si_code", &self.si_code)
            .finish()
    }
}

#[cfg(target_arch = "x86_64")]
#[allow(non_camel_case_types)]
pub type mcontext_t = x64::mcontext_t;
#[cfg(target_arch = "x86_64")]
#[allow(non_camel_case_types)]
pub type ucontext_t = x64::ucontext_t;

#[cfg(target_arch = "aarch64")]
#[allow(non_camel_case_types)]
pub type mcontext_t = aarch64::mcontext_t;
#[cfg(target_arch = "aarch64")]
#[allow(non_camel_case_types)]
pub type ucontext_t = aarch64::ucontext_t;

impl Debug for ucontext_t {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ucontext_t")
            .field("uc_flags", &self.uc_flags)
            .field("uc_link", &self.uc_link)
            .field("uc_stack", &self.uc_stack)
            .field("uc_mcontext", &self.uc_mcontext)
            .finish()
    }
}

#[cfg(target_arch = "x86_64")]
mod x64 {
    use crate::sys::stack_t;
    use core::fmt::Debug;

    extern "C" {
        /// Is defined in assembly.
        pub fn __sigreturn_x64();
    }

    #[repr(C)]
    // https://github.com/golang/go/blob/8db131082d08e497fd8e9383d0ff7715e1bef478/src/runtime/defs_linux_amd64.go#L246
    pub struct ucontext_t {
        pub uc_flags: u64,
        pub uc_link: *mut ucontext_t,
        pub uc_stack: stack_t,
        pub uc_mcontext: mcontext_t,
        __val: [u64; 16],
        __fpregs_mem: fpstate,
    }

    #[repr(C)]
    pub struct fpxreg {
        significand: [u16; 4],
        exponent: u16,
        padding: [u16; 3],
    }

    #[repr(C)]
    pub struct xmmreg {
        element: [u32; 4],
    }

    #[repr(C)]
    pub struct fpstate {
        cwd: u16,
        swd: u16,
        ftw: u16,
        fop: u16,
        rip: u64,
        rdp: u64,
        mxcsr: u32,
        mxcr_mask: u32,
        _st: [fpxreg; 8],
        _xmm: [xmmreg; 16],
        padding: [u32; 24],
    }

    #[repr(C)]
    pub struct mcontext_t {
        r8: u64,
        r9: u64,
        r10: u64,
        r11: u64,
        r12: u64,
        r13: u64,
        r14: u64,
        r15: u64,
        rdi: u64,
        rsi: u64,
        rbp: u64,
        rbx: u64,
        rdx: u64,
        rax: u64,
        rcx: u64,
        rsp: u64,
        rip: u64,
        eflags: u64,
        cs: u16,
        gs: u16,
        fs: u16,
        __pad0: u16,
        err: u64,
        trapno: u64,
        oldmask: u64,
        cr2: u64,
        fpstate: *mut fpstate,
        __reserved1: [u64; 8],
    }

    impl Debug for mcontext_t {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            let mut regs = f.debug_struct("regs");
            regs.field("rax", &(self.rax as *const u8))
                .field("rbx", &(self.rbx as *const u8))
                .field("rcx", &(self.rcx as *const u8))
                .field("rdx", &(self.rdx as *const u8))
                .field("rdi", &(self.rdi as *const u8))
                .field("rsi", &(self.rsi as *const u8))
                .field("rbp", &(self.rbp as *const u8))
                .field("rsp", &(self.rsp as *const u8))
                .field("r8", &(self.r8 as *const u8))
                .field("r9", &(self.r9 as *const u8))
                .field("r10", &(self.r10 as *const u8))
                .field("r11", &(self.r11 as *const u8))
                .field("r12", &(self.r12 as *const u8))
                .field("r13", &(self.r13 as *const u8))
                .field("r14", &(self.r14 as *const u8))
                .field("r15", &(self.r15 as *const u8));

            // Then print the struct
            regs.finish().unwrap();
            f.debug_struct("mcontext_t")
                .field("rip", &(self.rip as *const u8))
                .field("rsp", &(self.rsp as *const u8))
                .field("eflags", &self.eflags)
                .finish()
        }
    }

    impl mcontext_t {
        pub fn copy_restore_target_regs(&self, regs: &mut [usize; 16]) {
            // These registers are: rbx, rbp, r12, r13, r14, r15.
            // See section 3.2.3 and A.2.1 of https://refspecs.linuxfoundation.org/elf/x86_64-abi-0.99.pdf
            regs[0] = self.rbx as usize;
            regs[1] = self.rbp as usize;
            regs[2] = self.r12 as usize;
            regs[3] = self.r13 as usize;
            regs[4] = self.r14 as usize;
            regs[5] = self.r15 as usize;
            // Plus, r9, which seems weird, but musl libc does assume the preservation.
            // https://github.com/bminor/musl/blob/f314e133929b6379eccc632bef32eaebb66a7335/src/thread/x86_64/clone.s#L22C9-L22C11
            regs[6] = self.r9 as usize;
        }
    }

    // See https://man7.org/linux/man-pages/man2/syscall.2.html
    impl ucontext_t {
        pub fn syscall_arg1(&self) -> usize {
            self.uc_mcontext.rdi as usize
        }

        pub fn syscall_arg2(&self) -> (usize, usize) {
            (self.uc_mcontext.rdi as usize, self.uc_mcontext.rsi as usize)
        }

        pub fn syscall_arg3(&self) -> (usize, usize, usize) {
            (
                self.uc_mcontext.rdi as usize,
                self.uc_mcontext.rsi as usize,
                self.uc_mcontext.rdx as usize,
            )
        }

        pub fn syscall_arg4(&self) -> (usize, usize, usize, usize) {
            (
                self.uc_mcontext.rdi as usize,
                self.uc_mcontext.rsi as usize,
                self.uc_mcontext.rdx as usize,
                self.uc_mcontext.r10 as usize,
            )
        }

        pub fn syscall_arg5(&self) -> (usize, usize, usize, usize, usize) {
            (
                self.uc_mcontext.rdi as usize,
                self.uc_mcontext.rsi as usize,
                self.uc_mcontext.rdx as usize,
                self.uc_mcontext.r10 as usize,
                self.uc_mcontext.r8 as usize,
            )
        }

        pub fn syscall_arg6(&self) -> (usize, usize, usize, usize, usize, usize) {
            (
                self.uc_mcontext.rdi as usize,
                self.uc_mcontext.rsi as usize,
                self.uc_mcontext.rdx as usize,
                self.uc_mcontext.r10 as usize,
                self.uc_mcontext.r8 as usize,
                self.uc_mcontext.r9 as usize,
            )
        }

        pub fn syscall_no(&self) -> usize {
            // rax is the syscall number.
            self.uc_mcontext.rax as usize
        }

        pub fn set_syscall_ret(&mut self, ret: usize) {
            self.uc_mcontext.rax = ret as u64;
        }

        /// Returns the arguments of clone(2) in the order of flags, child_stack, ptid, tls, ctid.
        /// On x64, we need to swap the order of ctid and tls.
        pub fn clone_args(&self) -> (usize, usize, usize, usize, usize) {
            let (flags, child_stack, ptid, ctid, tls) = self.syscall_arg5();
            (flags, child_stack, ptid, tls, ctid)
        }

        pub fn return_address(&self) -> usize {
            self.uc_mcontext.rip as usize
        }

        pub fn stack_pointer(&self) -> usize {
            self.uc_mcontext.rsp as usize
        }
    }
}

#[cfg(target_arch = "aarch64")]
mod aarch64 {
    use crate::sys::stack_t;
    use core::fmt::Debug;

    #[repr(C)]
    // sysdeps/unix/sysv/linux/aarch64/sys/ucontext.h
    #[derive(Clone, PartialEq)]
    pub struct mcontext_t {
        pub fault_address: u64,
        pub regs: [u64; 31],
        pub sp: u64,
        pub pc: u64,
        pub pstate: u64,
        pub reserved: [u8; 4096],
    }

    #[repr(C)]
    // sysdeps/unix/sysv/linux/aarch64/sys/ucontext.h
    // https://github.com/golang/go/blob/8db131082d08e497fd8e9383d0ff7715e1bef478/src/runtime/defs_linux_arm64.go#L203
    #[derive(Clone, PartialEq)]
    pub struct ucontext_t {
        pub uc_flags: u64,
        pub uc_link: *mut ucontext_t,
        pub uc_stack: stack_t,
        pub uc_sigmask: u64,
        // sysdeps/unix/sysv/linux/bits/types/__sigset_t.h
        _padd: [u64; 1024 / (8 * 8)],
        pub uc_mcontext: mcontext_t,
    }

    impl Default for ucontext_t {
        fn default() -> Self {
            Self {
                uc_flags: 0,
                uc_link: core::ptr::null_mut::<ucontext_t>(),
                uc_stack: stack_t {
                    ss_sp: core::ptr::null_mut::<u8>(),
                    ss_flags: 0,
                    ss_size: 0,
                },
                uc_sigmask: 0,
                _padd: [0; 1024 / (8 * 8)],
                uc_mcontext: mcontext_t {
                    fault_address: 0,
                    regs: [0; 31],
                    sp: 0,
                    pc: 0,
                    pstate: 0,
                    reserved: [0; 4096],
                },
            }
        }
    }

    impl mcontext_t {
        pub fn copy_restore_target_regs(&self, regs: &mut [usize; 16]) {
            // x19-x29 are the restore targets.
            regs[0] = self.regs[19] as usize;
            regs[1] = self.regs[20] as usize;
            regs[2] = self.regs[21] as usize;
            regs[3] = self.regs[22] as usize;
            regs[4] = self.regs[23] as usize;
            regs[5] = self.regs[24] as usize;
            regs[6] = self.regs[25] as usize;
            regs[7] = self.regs[26] as usize;
            regs[8] = self.regs[27] as usize;
            regs[9] = self.regs[28] as usize;
            regs[10] = self.regs[29] as usize;
            regs[11] = self.regs[30] as usize;
        }
    }

    impl ucontext_t {
        pub fn syscall_arg1(&self) -> usize {
            self.uc_mcontext.regs[0] as usize
        }

        pub fn syscall_arg2(&self) -> (usize, usize) {
            (
                self.uc_mcontext.regs[0] as usize,
                self.uc_mcontext.regs[1] as usize,
            )
        }

        pub fn syscall_arg3(&self) -> (usize, usize, usize) {
            (
                self.uc_mcontext.regs[0] as usize,
                self.uc_mcontext.regs[1] as usize,
                self.uc_mcontext.regs[2] as usize,
            )
        }

        pub fn syscall_arg4(&self) -> (usize, usize, usize, usize) {
            (
                self.uc_mcontext.regs[0] as usize,
                self.uc_mcontext.regs[1] as usize,
                self.uc_mcontext.regs[2] as usize,
                self.uc_mcontext.regs[3] as usize,
            )
        }

        pub fn syscall_arg5(&self) -> (usize, usize, usize, usize, usize) {
            (
                self.uc_mcontext.regs[0] as usize,
                self.uc_mcontext.regs[1] as usize,
                self.uc_mcontext.regs[2] as usize,
                self.uc_mcontext.regs[3] as usize,
                self.uc_mcontext.regs[4] as usize,
            )
        }

        pub fn syscall_arg6(&self) -> (usize, usize, usize, usize, usize, usize) {
            (
                self.uc_mcontext.regs[0] as usize,
                self.uc_mcontext.regs[1] as usize,
                self.uc_mcontext.regs[2] as usize,
                self.uc_mcontext.regs[3] as usize,
                self.uc_mcontext.regs[4] as usize,
                self.uc_mcontext.regs[5] as usize,
            )
        }

        pub fn syscall_no(&self) -> usize {
            // x8 is the syscall number.
            self.uc_mcontext.regs[8] as usize
        }

        pub fn set_syscall_ret(&mut self, ret: usize) {
            self.uc_mcontext.regs[0] = ret as u64;
        }

        pub fn syscall_ret(&self) -> usize {
            self.uc_mcontext.regs[0] as usize
        }

        /// Returns the arguments of clone(2) in the order of flags, child_stack, ptid, tls, ctid.
        /// On AArch64, that is the same order as the syscall arguments.
        pub fn clone_args(&self) -> (usize, usize, usize, usize, usize) {
            self.syscall_arg5()
        }

        pub fn return_address(&self) -> usize {
            self.uc_mcontext.pc as usize
        }

        pub fn stack_pointer(&self) -> usize {
            self.uc_mcontext.sp as usize
        }
    }

    impl Debug for mcontext_t {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            // Pretty print the registers with x0-x30.
            let mut regs = f.debug_struct("regs");
            // Do not use for loop because it will panic if the range is out of bounds.
            regs.field("x0", &(self.regs[0] as *const u8))
                .field("x1", &(self.regs[1] as *const u8))
                .field("x2", &(self.regs[2] as *const u8))
                .field("x3", &(self.regs[3] as *const u8))
                .field("x4", &(self.regs[4] as *const u8))
                .field("x5", &(self.regs[5] as *const u8))
                .field("x6", &(self.regs[6] as *const u8))
                .field("x7", &(self.regs[7] as *const u8))
                .field("x8", &(self.regs[8] as *const u8))
                .field("x9", &(self.regs[9] as *const u8))
                .field("x10", &(self.regs[10] as *const u8))
                .field("x11", &(self.regs[11] as *const u8))
                .field("x12", &(self.regs[12] as *const u8))
                .field("x13", &(self.regs[13] as *const u8))
                .field("x14", &(self.regs[14] as *const u8))
                .field("x15", &(self.regs[15] as *const u8))
                .field("x16", &(self.regs[16] as *const u8))
                .field("x17", &(self.regs[17] as *const u8))
                .field("x18", &(self.regs[18] as *const u8))
                .field("x19", &(self.regs[19] as *const u8))
                .field("x20", &(self.regs[20] as *const u8))
                .field("x21", &(self.regs[21] as *const u8))
                .field("x22", &(self.regs[22] as *const u8))
                .field("x23", &(self.regs[23] as *const u8))
                .field("x24", &(self.regs[24] as *const u8))
                .field("x25", &(self.regs[25] as *const u8))
                .field("x26", &(self.regs[26] as *const u8))
                .field("x27", &(self.regs[27] as *const u8))
                .field("x28", &(self.regs[28] as *const u8))
                .field("x29", &(self.regs[29] as *const u8))
                .field("x30", &(self.regs[30] as *const u8));

            // Then print the struct
            regs.finish().unwrap();

            f.debug_struct("mcontext_t")
                .field("fault_address", &(self.fault_address as *const u8))
                .field("sp", &(self.sp as *const u8))
                .field("pc", &(self.pc as *const u8))
                .field("pstate", &self.pstate)
                .finish()
        }
    }
}

pub const SA_RESTART: i32 = 0x10000000;
pub const SA_ONSTACK: i32 = 0x8000000;
pub const SA_RESTORER: i32 = 0x04000000;
pub const SA_SIGINFO: i32 = 0x4;

pub const SIG_DFL: usize = 0;
pub const SIG_IGN: usize = 1;

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct SigAction {
    pub sa_sigaction: *mut u8,
    pub sa_flags: i32,
    pub _sa_restorer: usize,
    // sysdeps/unix/sysv/linux/arc/bits/types/__sigset_t.h
    pub sa_mask: u64,
}

impl Default for SigAction {
    fn default() -> Self {
        Self {
            sa_sigaction: SIG_DFL as *mut u8,
            sa_flags: 0,
            _sa_restorer: 0,
            sa_mask: 0,
        }
    }
}

pub fn sigaction(
    signum: usize,
    sa_sigaction: extern "C" fn(i32, &siginfo_t, &mut ucontext_t),
    sa_flags: i32,
    sa_mask: u64,
) {
    #[cfg(target_arch = "x86_64")]
    let (restorer, sa_flags) = {
        // https://github.com/golang/go/blob/8db131082d08e497fd8e9383d0ff7715e1bef478/src/runtime/os_linux.go#L468-L470
        // >> Although Linux manpage says "sa_restorer element is obsolete and
        // >> should not be used". x86_64 kernel requires it. Only use it on
        // >> x86.
        (x64::__sigreturn_x64 as usize, sa_flags | SA_RESTORER)
    };
    #[cfg(target_arch = "aarch64")]
    let restorer = 0;

    let mut act = SigAction {
        sa_sigaction: sa_sigaction as *mut u8,
        sa_mask,
        _sa_restorer: restorer,
        sa_flags,
    };

    unsafe {
        match syscall!(
            Sysno::rt_sigaction,
            signum,
            &mut act as *mut SigAction,
            0, // We don't care about the old action.
            8  // sizeof(sa_mask).
        ) {
            Ok(_) => (),
            Err(err) => panic!("sigaction failed: {}", err),
        }
    }

    // Sanity check.
    if cfg!(debug_assertions) {
        extern "C" fn tmp(_: i32, _: &siginfo_t, _: &mut ucontext_t) {}
        act.sa_sigaction = tmp as *mut u8;
        act.sa_flags = 0;
        let mut old = act;
        unsafe {
            syscall!(
                Sysno::rt_sigaction,
                signum,
                0,
                &mut old as *mut SigAction,
                8 // sizeof(sa_mask).
            )
            .expect("sigaction failed")
        };
        assert_eq!(old.sa_sigaction, sa_sigaction as *mut u8);
        assert_eq!(old.sa_flags, sa_flags);
    }
}

// https://github.com/torvalds/linux/blob/master/include/uapi/linux/seccomp.h
pub const SECCOMP_SET_MODE_STRICT: u32 = 0;
pub const SECCOMP_SET_MODE_FILTER: u32 = 1;
pub const SECCOMP_FILTER_FLAG_TSYNC: u32 = 1 << 0;
pub const SECCOMP_FILTER_FLAG_LOG: u32 = 1 << 1;
pub const SECCOMP_FILTER_FLAG_SPEC_ALLOW: u32 = 1 << 2;

pub fn seccomp(operation: u32, flags: u32, filter: *const u8) -> i32 {
    unsafe {
        match syscall!(Sysno::seccomp, operation, flags, filter) {
            Ok(result) => result as i32,
            Err(err) => panic!("seccomp failed: {}", err),
        }
    }
}

pub fn no_new_prev() {
    // Set the no new privs flag to be able to use seccomp.
    unsafe {
        // Execute: prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
        use syscalls::*;
        match syscall!(Sysno::prctl, 38, 1, 0, 0, 0) {
            Ok(_) => (),
            Err(err) => panic!("prctl failed: {}", err),
        }
    }
}

pub const SIG_BLOCK: i32 = 0;
pub const SIG_UNBLOCK: i32 = 1;
pub const SIG_SETMASK: i32 = 2;

pub fn sigprocmask_how_to_str(how: i32) -> &'static str {
    match how {
        SIG_BLOCK => "SIG_BLOCK",
        SIG_UNBLOCK => "SIG_UNBLOCK",
        SIG_SETMASK => "SIG_SETMASK",
        _ => "unknown",
    }
}

pub fn sigprocmask(how: i32, set: SigSet) -> SigSet {
    let oldset = 0 as SigSet;
    unsafe {
        match syscall!(
            Sysno::rt_sigprocmask,
            how,
            &set as *const SigSet,
            &oldset as *const SigSet,
            8 // sizeof(SigSet)
        ) {
            Ok(_) => {} // success
            Err(err) => {
                panic!("rt_sigprocmask failed: {}", err);
            }
        }
    }
    oldset
}

pub fn exit_group(status: i32) -> ! {
    unsafe {
        match syscall!(Sysno::exit_group, status) {
            Ok(_) => unreachable!(),
            Err(err) => panic!("exit_group failed: {}", err),
        }
    }
}

pub fn getcwd(buf: *mut u8, size: usize) -> *mut u8 {
    unsafe {
        match syscall!(Sysno::getcwd, buf, size) {
            Ok(result) => result as *mut u8,
            Err(err) => panic!("getcwd failed: {}", err),
        }
    }
}

// TODO: this is x86_64 specific, but the only info we need is the file size,
// whose offset is the same for at least x86_64 and aarch64.
// https://man7.org/linux/man-pages/man3/stat.3type.html
#[repr(C)]
#[derive(Default)]
pub struct stat_t {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_nlink: u64,
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub __pad0: u32,
    pub st_rdev: u64,
    pub st_size: i64,
    pub st_blksize: i64,
    pub st_blocks: i64,
    pub st_atime: i64,
    pub st_atime_nsec: i64,
    pub st_mtime: i64,
    pub st_mtime_nsec: i64,
    pub st_ctime: i64,
    pub st_ctime_nsec: i64,
    pub __unused: [i64; 3],
}

pub fn fstat(fd: i32, st: &mut stat_t) -> Result<(), Errno> {
    unsafe {
        match syscall!(Sysno::fstat, fd, st as *mut stat_t) {
            Ok(_) => Ok(()),
            Err(err) => Err(err),
        }
    }
}

pub fn mkdir(path: *const u8, mode: u32) -> Result<(), Errno> {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        match syscall!(Sysno::mkdirat, AT_FDCWD, path, mode) {
            Ok(_) => Ok(()),
            Err(err) => Err(err),
        }
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        match syscall!(Sysno::mkdir, path, mode) {
            Ok(_) => Ok(()),
            Err(err) => Err(err),
        }
    }
}

pub const AT_FDCWD: i32 = -100;

pub fn getrandom(buf: &[u8]) -> Result<(), Errno> {
    unsafe {
        match syscall!(Sysno::getrandom, buf.as_ptr(), buf.len(), 0) {
            Ok(_) => Ok(()),
            Err(err) => Err(err),
        }
    }
}

pub fn mk_tmp_dir(buf: &mut [u8]) {
    assert!(buf.len() >= 12);
    buf[0..12].copy_from_slice(b"/tmp/tvisor-");
    getrandom(&buf[12..]).unwrap();
    // Random bytes are not necessarily printable, so we need to convert them to
    // printable characters.
    for b in buf.iter_mut().skip(12) {
        *b = b'a' + *b % 26;
    }
    mkdir(buf.as_ptr(), 0o755).unwrap();
}

pub fn readlink(path: *const u8, buf: &[u8]) -> Result<usize, Errno> {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        syscall!(Sysno::readlinkat, AT_FDCWD, path, buf.as_ptr(), buf.len())
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        syscall!(Sysno::readlink, path, buf.as_ptr(), buf.len())
    }
}

pub fn copy_file_range(fd_in: i32, fd_out: i32, size: usize) -> Result<usize, Errno> {
    unsafe { syscall!(Sysno::copy_file_range, fd_in, 0, fd_out, 0, size, 0) }
}

pub const SEEK_SET: i32 = 0;
pub const SEEK_CUR: i32 = 1;
pub const SEEK_END: i32 = 2;

pub fn lseek(fd: i32, offset: i64, whence: i32) -> Result<usize, Errno> {
    unsafe { syscall!(Sysno::lseek, fd, offset, whence) }
}

pub const O_RDONLY: i32 = 0;
pub const O_WRONLY: i32 = 1;
pub const O_RDWR: i32 = 2;
pub const O_CREAT: i32 = 0x40;
pub const O_APPEND: i32 = 0x400;

pub fn open(path: *const u8, flags: i32, mode: u32) -> Result<usize, Errno> {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        syscall!(Sysno::openat, AT_FDCWD, path, flags, mode)
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        syscall!(Sysno::open, path, flags, mode)
    }
}

pub fn read(fd: i32, buf: &[u8]) -> Result<usize, Errno> {
    unsafe { syscall!(Sysno::read, fd, buf.as_ptr(), buf.len()) }
}

pub fn write(fd: i32, buf: &[u8]) -> Result<usize, Errno> {
    unsafe { syscall!(Sysno::write, fd, buf.as_ptr(), buf.len()) }
}

pub fn close(fd: i32) -> Result<usize, Errno> {
    unsafe { syscall!(Sysno::close, fd) }
}

pub fn unlink(path: *const u8) -> Result<usize, Errno> {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        syscall!(Sysno::unlinkat, AT_FDCWD, path, 0)
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        syscall!(Sysno::unlink, path)
    }
}

pub fn rmdir(path: *const u8) -> Result<usize, Errno> {
    const AT_REMOVEDIR: i32 = 0x200;
    #[cfg(target_arch = "aarch64")]
    unsafe {
        syscall!(Sysno::unlinkat, AT_FDCWD, path, AT_REMOVEDIR)
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        syscall!(Sysno::rmdir, path)
    }
}

pub const CLONE_VM: usize = 0x100; // Run in the same memory space as the calling process
pub const CLONE_FS: usize = 0x200; // Share the same filesystem information
pub const CLONE_FILES: usize = 0x400; // Share the same file descriptor table
pub const CLONE_SIGHAND: usize = 0x800; // Share the same signal handler table
pub const CLONE_THREAD: usize = 0x10000; // Same thread group
pub const CLONE_SYSVSEM: usize = 0x40000; // Share the same System V semaphore adjustment
pub const CLONE_SETTLS: usize = 0x80000; // Caller will set the TLS for the new thread
pub const CLONE_PARENT_SETTID: usize = 0x100000; // Set the TID in the parent
pub const CLONE_CHILD_CLEARTID: usize = 0x200000; // Clear the TID in the child

pub fn __get_tp() -> usize {
    let tp: usize;
    #[cfg(target_arch = "aarch64")]
    // https://github.com/bminor/musl/blob/f314e133929b6379eccc632bef32eaebb66a7335/arch/aarch64/pthread_arch.h
    unsafe {
        asm!("mrs {}, tpidr_el0", out(reg) tp)
    }
    #[cfg(target_arch = "x86_64")]
    // https://github.com/bminor/musl/blob/f314e133929b6379eccc632bef32eaebb66a7335/arch/x86_64/pthread_arch.h
    unsafe {
        asm!("mov {}, fs:0", out(reg) tp)
    }
    tp
}

pub fn tgsigqueueinfo(
    pid: i32,
    tid: i32,
    sig: i32,
    uinfo: *const siginfo_t,
) -> Result<usize, Errno> {
    unsafe { syscall!(Sysno::rt_tgsigqueueinfo, pid, tid, sig, uinfo as usize) }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_case;

    test_case!(test_readlink, {
        let stdin = b"/proc/self/fd/1\0";
        let mut buf = [0u8; 4096];
        let len = readlink(stdin.as_ptr(), &mut buf).unwrap();
        let exp = b"/dev/pts/";
        // Compare as strings by converting to str.
        assert_eq!(
            unsafe { core::str::from_utf8_unchecked(&buf[0..len - 1]) },
            unsafe { core::str::from_utf8_unchecked(exp) }
        );
    });

    test_case!(test_mk_tmp_dir, {
        let buf = &mut [0u8; 32];
        mk_tmp_dir(buf);
        rmdir(buf.as_ptr()).unwrap();
    });

    test_case!(test_copy_file_range, {
        // Create two temporary files and then test copy_file_range.
        let buf = &mut [0u8; 32];
        mk_tmp_dir(&mut buf[0..31]);
        // Use buf as the temporary directory name.
        let src = format!("{}/src.txt\0", unsafe {
            core::str::from_utf8_unchecked(&buf[..31])
        });
        let dst = format!("{}/dst.txt\0", unsafe {
            core::str::from_utf8_unchecked(&buf[..31])
        });
        let src_fd = open(src.as_ptr(), O_CREAT | O_RDWR, 0o644).unwrap() as i32;
        let dst_fd = open(dst.as_ptr(), O_CREAT | O_RDWR, 0o644).unwrap() as i32;
        let src_content = b"hello world";
        write(src_fd, src_content).unwrap();
        // seek to the beginning of the file.
        lseek(src_fd, 0, SEEK_SET).unwrap();
        let ret = copy_file_range(src_fd, dst_fd, src_content.len()).unwrap();
        assert_eq!(ret, src_content.len());
        let mut content = [0u8; 32];
        lseek(dst_fd, 0, SEEK_SET).unwrap();
        read(dst_fd, &mut content).unwrap();
        // Compare as strings by converting to str.
        assert_eq!(
            unsafe { core::str::from_utf8_unchecked(&content[0..ret]) },
            unsafe { core::str::from_utf8_unchecked(src_content) }
        );
        close(src_fd).unwrap();
        close(dst_fd).unwrap();
        unlink(src.as_ptr()).unwrap();
        unlink(dst.as_ptr()).unwrap();
        rmdir(buf.as_ptr()).unwrap();
    });
}
