use crate::bpf::{sock_filter, sock_fprog};
use crate::global::{ChildThreadState, GlobalState};
use crate::signals;
use crate::signals::SigSet;
use crate::sync::ThreadSync;
use crate::sys::{mcontext_t, ucontext_t, CLONE_VM};
use crate::{debug_println, kernel_debug_println, kernel_panic, util, ORIGINAL_ARGV, PAGE_SIZE};
use crate::{sys, STACK_SIZE};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt::Debug;
use syscalls::Sysno;

macro_rules! kernel_syscall_unimplemented {
    ($name:ident) => {
        fn $name(&mut self, _ucontext: &mut ucontext_t) {
            unimplemented!(stringify!($name))
        }
    };
}

pub trait Kernel: Debug + Default + Clone {
    fn syscall_nos() -> &'static [Sysno];
    fn help();
    fn init(&mut self, _args: &mut crate::ArgsIter<Self>) {
        for _arg in _args.by_ref() {}
    }

    // Syscall handlers.
    kernel_syscall_unimplemented!(writev);
    #[cfg(target_arch = "x86_64")]
    kernel_syscall_unimplemented!(open);
    kernel_syscall_unimplemented!(openat);
    kernel_syscall_unimplemented!(getcwd);
    kernel_syscall_unimplemented!(exit_group);
    kernel_syscall_unimplemented!(getuid);

    fn nanosleep(&mut self, ucontext: &mut ucontext_t) {
        let (req, rem) = ucontext.syscall_arg2();
        let ret = unsafe { syscalls::raw_syscall!(Sysno::nanosleep, req, rem) };
        ucontext.set_syscall_ret(ret);
    }

    fn clock_nanosleep(&mut self, ucontext: &mut ucontext_t) {
        let (clock_id, flags, req, rem) = ucontext.syscall_arg4();
        let ret =
            unsafe { syscalls::raw_syscall!(Sysno::clock_nanosleep, clock_id, flags, req, rem) };
        ucontext.set_syscall_ret(ret);
    }

    // TODO: add more syscalls.
}

pub const CLONE_GUEST_SHARED_FLAG: usize = sys::CLONE_VM
    | sys::CLONE_FS
    | sys::CLONE_FILES
    | sys::CLONE_SIGHAND
    | sys::CLONE_SYSVSEM
    | sys::CLONE_THREAD
    | sys::CLONE_SETTLS
    | sys::CLONE_PARENT_SETTID
    | sys::CLONE_CHILD_CLEARTID;

pub struct KernelThread<'a, T: Kernel> {
    channel: SandboxChannel,
    kernel: &'a mut T,
    guest_child_arg: StartGuestChildThreadArg,
}

#[repr(C)]
pub struct SandboxChannel {
    pub thread_sync: ThreadSync,
    pub sig_data: signals::SigData,
    pub seccomp_prog: sock_fprog,
    pub initial_sigmask: SigSet,
    pub global_state: *mut u8,
    pub kernel_thread_id: usize,
    pub thread_state_ptr: *mut u8,
}

impl<'a, T: Kernel + 'a> KernelThread<'a, T> {
    fn new(k: &'a mut T, initial_sigmask: SigSet, global_state: *mut GlobalState) -> Self {
        let kernel_thread_id = sys::gettid();
        Self {
            channel: SandboxChannel {
                thread_sync: ThreadSync::new(),
                sig_data: signals::SigData::default(),
                seccomp_prog: sock_fprog {
                    len: 0,
                    filter: core::ptr::null(),
                },
                initial_sigmask,
                global_state: global_state as *mut u8,
                kernel_thread_id,
                thread_state_ptr: core::ptr::null_mut(),
            },
            guest_child_arg: StartGuestChildThreadArg {
                entry_point: 0,
                channel: core::ptr::null_mut(),
                restore_regs: [0; 16],
            },
            kernel: k,
        }
    }

    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn start(k: &'a mut T, clone_guest_arg: &CloneGuestArgs) -> ! {
        let kt = Box::leak(Box::new(Self::new(k, 0, clone_guest_arg.global_state)));

        // Kernel thread should not get interrupted by signals.
        signals::block_all_signals();

        // Initialize the seccomp filter.
        let filter = construct_seccomp_bpf_filter(T::syscall_nos());
        assert!(filter.len() <= u16::MAX as usize);
        kt.channel.seccomp_prog = sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_ptr(),
        };

        // Start the guest thread.
        kernel_debug_println!(
            "starting guest main thread at {:p}",
            clone_guest_arg.guest_entrypoint,
        );

        let tid = unsafe {
            let arg = StartGuestMainThreadArg {
                entry_point: clone_guest_arg.guest_entrypoint,
                channel: &mut kt.channel as *mut SandboxChannel,
            };

            start_guest_main_thread(
                CLONE_GUEST_SHARED_FLAG,
                clone_guest_arg.guest_child_stack,
                clone_guest_arg.guest_ptid,
                clone_guest_arg.guest_tls,
                clone_guest_arg.guest_ctid,
                &arg,
            )
        };

        kernel_debug_println!(
            "guest main thread started: tid={}, sandbox_channel={:p}",
            tid,
            &mut kt.channel,
        );

        kt.start_monitoring(tid)
    }

    fn start_monitoring(&mut self, child_tid: i32) -> ! {
        let sandbox_channel = &mut self.channel;

        let pid = sys::getpid();
        let tid = sys::gettid();

        loop {
            kernel_debug_println!("waiting for guest");
            sandbox_channel.thread_sync.parent_enter();
            kernel_debug_println!("message from guest");

            if !sandbox_channel.sig_data.info.is_null() {
                let ucontext = sandbox_channel.sig_data.ucontext();

                let syscall_no = syscalls::Sysno::from(ucontext.syscall_no() as i32);
                kernel_debug_println!("syscall = {}", syscall_no);

                match syscall_no {
                    Sysno::writev => self.kernel.writev(ucontext),
                    #[cfg(target_arch = "x86_64")]
                    Sysno::open => self.kernel.open(ucontext),
                    Sysno::openat => self.kernel.openat(ucontext),
                    Sysno::getcwd => self.kernel.getcwd(ucontext),
                    Sysno::getuid => self.kernel.getuid(ucontext),
                    Sysno::exit_group => self.kernel.exit_group(ucontext),
                    Sysno::nanosleep => self.kernel.nanosleep(ucontext),
                    Sysno::clock_nanosleep => self.kernel.clock_nanosleep(ucontext),
                    Sysno::clone => {
                        let (flags, child_stack, ptid, tls, ctid) = ucontext.clone_args();
                        let ret = if let Err(err) = check_clone_flags(flags) {
                            -err as usize
                        } else {
                            let tp = sandbox_channel.sig_data.clone_caller_thread_local;
                            let sigmask = sandbox_channel.sig_data.clone_caller_sigmask;
                            let kernel = Box::leak(Box::new(self.kernel.clone()));
                            let global_state = sandbox_channel.global_state;
                            Self::clone(
                                kernel,
                                flags,
                                child_stack,
                                ptid,
                                tls,
                                ctid,
                                ucontext,
                                tp,
                                sigmask,
                                global_state as *mut GlobalState,
                            ) as usize
                        };
                        ucontext.set_syscall_ret(ret);
                    }
                    Sysno::execve => Self::execve(ucontext),
                    _ => {
                        kernel_panic!("unimplemented syscall: {}", syscall_no);
                    }
                }
            }

            // Before woke up the guest thread, check the pending signals.
            let child_thread_mask = {
                let child_state =
                    unsafe { &*(sandbox_channel.thread_state_ptr as *mut ChildThreadState) };
                &child_state.sig_mask
            };
            let global_state = unsafe { &mut *(sandbox_channel.global_state as *mut GlobalState) };
            let pending_sigmask =
                global_state.pending_signal_handling_candidates(child_thread_mask);
            if pending_sigmask != 0 {
                kernel_debug_println!(
                    "Pending signals found: {}. Sending SIGILL to the guest thread {}.",
                    signals::sigmask_to_string(pending_sigmask),
                    child_tid,
                );
                let mut sig_info = sys::siginfo_t::default();
                sig_info.si_signo = signals::SIGILL as i32;
                sig_info.si_code = sys::SI_QUEUE;
                sig_info.set_si_pid(-(tid as isize) as usize);
                sys::tgsigqueueinfo(pid as i32, child_tid, signals::SIGILL as i32, &sig_info)
                    .expect("tgsigqueueinfo");
            };

            kernel_debug_println!("wake up guest");
            sandbox_channel.thread_sync.parent_exit();
        }
    }

    pub fn execve(ucontext: &mut ucontext_t) {
        let (filename, argv, envp) = ucontext.syscall_arg3();
        kernel_debug_println!(
            "execve: filename = {:?}",
            util::cstr_from_ptr(filename as *const u8)
        );
        let mut new_args = Vec::<*const u8>::new();
        let mut cur = 0;
        let tvisor_bin_path = unsafe { *ORIGINAL_ARGV };
        loop {
            let ptr = unsafe { *ORIGINAL_ARGV.offset(cur) };
            assert!(!ptr.is_null());
            let arg = util::cstr_from_ptr(ptr);
            new_args.push(ptr);
            cur += 1;
            if arg == "--" {
                break;
            }
        }
        new_args.push(filename as *const u8);
        if argv != 0 {
            let argv = argv as *const *const u8;
            let mut cur = 0;
            loop {
                let ptr = unsafe { *argv.offset(cur) };
                if ptr.is_null() {
                    break;
                }
                kernel_debug_println!("execve: argv[{cur}] = {:?}", util::cstr_from_ptr(ptr));
                new_args.push(ptr);
                cur += 1;
            }
        }
        new_args.push(core::ptr::null());
        for (i, arg) in new_args.iter().enumerate() {
            if arg.is_null() {
                break;
            }
            kernel_debug_println!("execve: new_args[{i}] {:?}", util::cstr_from_ptr(*arg));
        }

        let ret = unsafe {
            syscalls::raw_syscall!(Sysno::execve, tvisor_bin_path, new_args.as_ptr(), envp)
        };

        ucontext.set_syscall_ret(ret);
    }

    #[allow(clippy::too_many_arguments)]
    fn clone(
        k: &mut T,
        flags: usize,
        child_stack: usize,
        ptid: usize,
        tls: usize,
        ctid: usize,
        ucontext: &mut ucontext_t,
        caller_tp: usize,
        caller_sigmask: SigSet,
        global_state: *mut GlobalState,
    ) -> i32 {
        const STACK_MMAP_SIZE: usize = STACK_SIZE + PAGE_SIZE;
        let stack_bottom = sys::mmap(
            0,
            STACK_MMAP_SIZE,
            sys::PROT_READ | sys::PROT_WRITE,
            sys::MAP_PRIVATE | sys::MAP_ANONYMOUS,
        );

        // And set the guard page.
        sys::mprotect(stack_bottom, PAGE_SIZE, sys::PROT_NONE);
        let stack_top = unsafe { stack_bottom.add(STACK_MMAP_SIZE) };

        let entrypoint = ucontext.return_address();
        let mut clone_guest_args = CloneGuestArgs {
            raw_parent_kernel_sync: core::ptr::null_mut(),
            raw_child_guest_thread_id_ptr: core::ptr::null_mut(),
            guest_entrypoint: entrypoint as *mut u8,
            // https://man7.org/linux/man-pages/man2/clone.2.html
            //  >> In the case where the CLONE_VM flag (see below) is
            //  >> specified, a stack must be explicitly allocated and specified.
            //  >> Otherwise, these two fields can be specified as NULL and 0, which
            //  >> causes the child to use the same stack area as the parent (in the
            //  >> child's own virtual address space).
            guest_child_stack: if flags & CLONE_VM != 0 {
                child_stack as *mut u8
            } else {
                ucontext.uc_mcontext.sp as *mut u8
            },
            guest_ptid: ptid,
            guest_tls: tls as *mut u8,
            guest_ctid: ctid,
            mcontext: &ucontext.uc_mcontext as *const mcontext_t,
            global_state,
        };

        kernel_debug_println!(
            "clone: rip={:x}, stack={:x}, tls={:x}",
            entrypoint,
            child_stack,
            tls
        );

        let new_new_process = flags & sys::CLONE_THREAD == 0;
        if new_new_process {
            let clone_guest_args = CloneKernelArgs {
                raw_kernel: k as *mut T as *mut u8,
                raw_clone_guest_args: &clone_guest_args as *const CloneGuestArgs as *mut u8,
                original_clone_flag: flags,
                caller_tp,
                caller_sigmask,
            };
            let pid = unsafe { clone_kernel_thread(flags, stack_top, &clone_guest_args) };

            kernel_debug_println!("clone: child kernel thread forked: {pid}");
            pid
        } else {
            let mut sync = ThreadSync::new();
            let child_guest_thread_id: i32 = 0;
            clone_guest_args.raw_child_guest_thread_id_ptr =
                &child_guest_thread_id as *const i32 as *mut i32;
            clone_guest_args.raw_parent_kernel_sync = &mut sync as *mut ThreadSync;

            let clone_guest_args = CloneKernelArgs {
                raw_kernel: k as *mut T as *mut u8,
                raw_clone_guest_args: &clone_guest_args as *const CloneGuestArgs as *mut u8,
                original_clone_flag: flags,
                caller_tp, // Though, this is not used in non-fork case.
                caller_sigmask,
            };

            let tid = unsafe { clone_kernel_thread(flags, stack_top, &clone_guest_args) };
            kernel_debug_println!(
                "clone: child kernel thread started: {}. Waiting for the child guest thread starts.",
                tid
            );

            // Wait for the child thread to be ready.
            sync.parent_enter();
            kernel_debug_println!(
                "clone: child guest thread is ready = {}",
                child_guest_thread_id
            );
            child_guest_thread_id
        }
    }

    pub fn cloned_kernel_main(raw_clone_kernel_args: *mut u8) -> ! {
        let clone_kernel_args = unsafe { &*(raw_clone_kernel_args as *const CloneKernelArgs) };
        let k = unsafe { &mut *(clone_kernel_args.raw_kernel as *mut T) };
        let clone_guest_args =
            unsafe { &mut *(clone_kernel_args.raw_clone_guest_args as *mut CloneGuestArgs) };
        let original_clone_flag = clone_kernel_args.original_clone_flag;
        let caller_tp = clone_kernel_args.caller_tp;
        let caller_sigmask = clone_kernel_args.caller_sigmask;
        Self::start_child(
            k,
            clone_guest_args,
            original_clone_flag,
            caller_tp,
            caller_sigmask,
        );
    }

    fn start_child(
        k: &'a mut T,
        clone_guest_arg: &mut CloneGuestArgs,
        original_clone_flag: usize,
        caller_tp: usize,
        caller_sigmask: SigSet,
    ) -> ! {
        let kt = Box::leak(Box::new(Self::new(
            k,
            caller_sigmask,
            clone_guest_arg.global_state,
        )));
        // Kernel thread should not get interrupted by signals.
        signals::block_all_signals();

        // Initialize the seccomp filter.
        let filter = construct_seccomp_bpf_filter(T::syscall_nos());
        assert!(filter.len() <= u16::MAX as usize);
        kt.channel.seccomp_prog = sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_ptr(),
        };

        let child_guest_thread_id_ptr = clone_guest_arg.raw_child_guest_thread_id_ptr;

        // Start the guest thread.
        kernel_debug_println!(
            "starting guest child thread at {:p}",
            clone_guest_arg.guest_entrypoint,
        );

        let is_fork = original_clone_flag & sys::CLONE_THREAD == 0;

        let tid = unsafe {
            kt.guest_child_arg.entry_point = clone_guest_arg.guest_entrypoint as usize;
            kt.guest_child_arg.channel = &mut kt.channel as *mut SandboxChannel;
            (*clone_guest_arg.mcontext)
                .copy_restore_target_regs(&mut kt.guest_child_arg.restore_regs);

            let arg = &kt.guest_child_arg;

            kernel_debug_println!(
                "child guest thread: entry_point={:x}, arg={:p}, guest_child_stack={:p}",
                kt.guest_child_arg.entry_point,
                arg,
                clone_guest_arg.guest_child_stack
            );

            let mut flag = CLONE_GUEST_SHARED_FLAG;
            if is_fork {
                if original_clone_flag & sys::CLONE_SETTLS != 0 {
                    kernel_debug_println!("TODO?: setting TLS while forking a new process");
                } else {
                    clone_guest_arg.guest_tls = caller_tp as *mut u8;
                    flag |= sys::CLONE_SETTLS;
                }
            }

            kernel_debug_println!(
                "child guest thread: guest_child_tls={:p}",
                clone_guest_arg.guest_tls
            );

            start_guest_child_thread(
                flag,
                clone_guest_arg.guest_child_stack,
                clone_guest_arg.guest_ptid,
                clone_guest_arg.guest_tls,
                clone_guest_arg.guest_ctid,
                arg,
            )
        };

        // If this is the fork, no need to notify the parent.
        if !is_fork {
            // Notify the child guest thread ID to the parent kernel thread.
            unsafe {
                *child_guest_thread_id_ptr = tid;
            }

            let thread_sync = clone_guest_arg.raw_parent_kernel_sync;
            debug_assert!(
                !thread_sync.is_null(),
                "parent_kernel_futex must not be null"
            );

            kernel_debug_println!(
                "main: child guest thread ID = {}. Notify the parent kernel thread.",
                tid
            );

            // Notify the parent kernel thread that the child guest thread is ready.
            let thread_sync = unsafe { &mut *thread_sync };
            thread_sync.child_exit();
        }

        kernel_debug_println!(
            "guest child thread started: tid={}, sandbox_channel={:p}",
            tid,
            &mut kt.channel,
        );

        kt.start_monitoring(tid)
    }
}

static MANDATORY_SYSCALLS: &[Sysno] = &[
    Sysno::sigaltstack,
    Sysno::rt_sigaction,
    Sysno::rt_sigprocmask,
    Sysno::clone,
    // https://github.com/google/gvisor/blob/b07b6076cb793e674c4b7b7dc6e339b0beb8099d/pkg/sentry/kernel/task_exec.go#L17
    Sysno::execve,
    Sysno::nanosleep,
    Sysno::clock_nanosleep,
];

fn construct_seccomp_bpf_filter(syscalls: &[Sysno]) -> Vec<sock_filter> {
    let syscall_num = syscalls.len() + MANDATORY_SYSCALLS.len();
    let program_size = syscall_num + 3;
    let mut filters = Vec::<sock_filter>::with_capacity(program_size);
    filters.push(sock_filter::load_syscall_no());
    for (j, &syscall) in syscalls.iter().chain(MANDATORY_SYSCALLS.iter()).enumerate() {
        filters.push(sock_filter::jeq_k(
            syscall as u32,
            (syscall_num - j) as u8,
            0,
        ));
    }
    filters.push(sock_filter::return_allow());
    filters.push(sock_filter::return_trap());
    assert_eq!(filters.len(), program_size);
    filters
}

#[repr(C)]
struct CloneKernelArgs {
    raw_kernel: *mut u8,
    raw_clone_guest_args: *mut u8,
    original_clone_flag: usize,
    caller_tp: usize,
    caller_sigmask: SigSet,
}

#[repr(C)]
pub struct CloneGuestArgs {
    pub raw_parent_kernel_sync: *mut ThreadSync,
    pub raw_child_guest_thread_id_ptr: *mut i32,
    pub guest_entrypoint: *mut u8,
    pub guest_child_stack: *mut u8,
    pub guest_ptid: usize,
    pub guest_tls: *mut u8,
    pub guest_ctid: usize,
    pub mcontext: *const mcontext_t,
    pub global_state: *mut GlobalState,
}

#[repr(C)]
struct StartGuestMainThreadArg {
    entry_point: *mut u8,
    channel: *mut SandboxChannel,
}

#[repr(C)]
struct StartGuestChildThreadArg {
    entry_point: usize,
    channel: *mut SandboxChannel,
    restore_regs: [usize; 16],
}

extern "C" {
    fn clone_kernel_thread(
        flags: usize,
        stack: *mut u8,
        clone_kernel_args: &CloneKernelArgs,
    ) -> i32;

    fn start_guest_main_thread(
        flags: usize,
        stack: *mut u8,
        parent_tidptr: usize,
        tls: *mut u8,
        child_tidptr: usize,
        arg: &StartGuestMainThreadArg,
    ) -> i32;

    fn start_guest_child_thread(
        flags: usize,
        stack: *mut u8,
        parent_tidptr: usize,
        tls: *mut u8,
        child_tidptr: usize,
        arg: &StartGuestChildThreadArg,
    ) -> i32;
}

fn check_clone_flags(flags: usize) -> Result<(), i32> {
    use sys::*;

    // According to the man page, CLONE_VM and CLONE_SIGHAND must be
    // specified together.
    if flags & (CLONE_SIGHAND | CLONE_VM) == (CLONE_SIGHAND) {
        kernel_debug_println!("CLONE_VM must be specified with CLONE_SIGHAND");
        return Err(EINVAL);
    }

    if flags & (CLONE_THREAD | CLONE_SIGHAND) == CLONE_THREAD {
        kernel_debug_println!("CLONE_THREAD must be specified with CLONE_SIGHAND");
        return Err(EINVAL);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_case;
    use sys::*;
    use syscalls::Sysno;

    test_case!(test_check_clone_flags, {
        assert_eq!(check_clone_flags(CLONE_SIGHAND), Err(EINVAL));
        assert_eq!(check_clone_flags(CLONE_THREAD), Err(EINVAL));
        assert_eq!(check_clone_flags(CLONE_VM | CLONE_SIGHAND), Ok(()));
        assert_eq!(
            check_clone_flags(CLONE_VM | CLONE_THREAD | CLONE_SIGHAND),
            Ok(())
        );
    });

    test_case!(test_construct_seccomp_bpf_filter, {
        let syscalls = &[Sysno::exit_group, Sysno::openat];
        let _ = construct_seccomp_bpf_filter(syscalls);
    });
}
