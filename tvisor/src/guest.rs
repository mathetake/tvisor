use crate::bpf::sock_fprog;
use crate::global::{ChildThreadState, GlobalState};
use crate::signals::{synchronous_signal, unblock_all_signals, SigData, SigSet};
use crate::sync::ThreadSync;
use crate::sys::{siginfo_t, stack_t, ucontext_t, SigAction};
use crate::{debug_println, guest_debug_println, kernel, signals, sys};
use alloc::boxed::Box;
use alloc::string::ToString;
use syscalls::Sysno;

const _GUEST_FUTEX_OFFSET: isize = 8;
const THREAD_SYNC_OFFSET: isize = 16;
const SIG_DATA_OFFSET: isize = 24;
const GLOBAL_STATE_OFFSET: isize = 32;
const SIG_ALTSTACK_OFFSET: isize = 40;
const THREAD_STATE_PTR_OFFSET: isize = 56;
const KERNEL_THREAD_ID_OFFSET: isize = 64;
const STACK_DATA_TOTAL_SIZE: usize = 72;
const STACK_DATA_TOTAL_SIZE_ALIGNED: usize = (STACK_DATA_TOTAL_SIZE + 0xf) & !0xf;
const SIGNAL_STACK_SIZE: usize = 0x20000 - STACK_DATA_TOTAL_SIZE + STACK_DATA_TOTAL_SIZE_ALIGNED;

#[no_mangle]
unsafe extern "C" fn guest_thread_init(channel: *mut kernel::SandboxChannel) {
    let channel = &mut *channel;
    guest_debug_println!(
        "guest_thread_init: sandbox_channel={:p}, initial_sigmask={}",
        channel,
        signals::sigmask_to_string(channel.initial_sigmask)
    );

    // Set up the signal stack.
    let signal_stack_top = sys::mmap(
        0usize,
        SIGNAL_STACK_SIZE + STACK_DATA_TOTAL_SIZE,
        sys::PROT_READ | sys::PROT_WRITE,
        sys::MAP_PRIVATE | sys::MAP_ANONYMOUS,
    );

    let thread_state_ptr = Box::into_raw(Box::new(ChildThreadState::new(
        // At this point, we block all signals as we haven't setup seccomp yet.
        !0,
    )));
    channel.thread_state_ptr = thread_state_ptr as *mut u8;

    // Advance the stack pointer to the end of the stack but leave STACK_DATA_TOTAL_SIZE bytes.
    let signal_stack_sp = signal_stack_top.add(SIGNAL_STACK_SIZE);
    // Write data to the above of the signal stack so that the signal handler can access them to proxy syscalls.
    set_thread_sync(signal_stack_sp, &mut channel.thread_sync);
    set_sig_data(signal_stack_sp, &mut channel.sig_data);
    set_child_thread_state_ptr(signal_stack_sp, thread_state_ptr);
    set_global_state(signal_stack_sp, channel.global_state as *mut GlobalState);
    set_kernel_thread_id(signal_stack_sp, channel.kernel_thread_id);

    guest_debug_println!("signal stack initialized. trying to set the signal stack");
    sys::sigaltstack(signal_stack_top, SIGNAL_STACK_SIZE);
    guest_debug_println!("signal stack set");

    // After setting up the signal stack, unblock all signals.
    unblock_all_signals();

    sys::seccomp(
        sys::SECCOMP_SET_MODE_FILTER,
        0,
        &channel.seccomp_prog as *const sock_fprog as *const u8,
    );
    guest_debug_println!("seccomp filter installed");

    // Now we are ready to set up the signal mask.
    let thread_state_ptr = channel.thread_state_ptr as *mut ChildThreadState;
    let thread_state = &mut *thread_state_ptr;
    thread_state.sig_mask = channel.initial_sigmask;

    // Initialize the thread state in the global state.
    let global_state = &mut *(channel.global_state as *mut GlobalState);
    global_state.add_new_child_thread(thread_state_ptr);

    // TODO: what if a signal arrives between here and the guest code?
}

pub fn handle_non_syscall_signal(sig: usize, info: &siginfo_t, ucontext: &mut ucontext_t) {
    let sp = ucontext.uc_stack.stack_end();
    assert!(
        !sp.is_null(),
        "signal stack pointer is null when handling {} ({}): {:?}",
        signals::sig_to_string(sig),
        sig,
        ucontext,
    );
    let thread_state = unsafe { &mut *get_child_thread_state_ptr(sp) };
    let global_state = unsafe { &mut *get_global_state(sp) };
    if info.si_code == sys::SI_QUEUE {
        let sender_pid = -(info.get_si_pid() as isize) as usize;
        guest_debug_println!(
            "sender_pid = {} for signal {}",
            sender_pid,
            signals::sig_to_string(sig),
        );
        if sender_pid == get_kernel_thread_id(sp) {
            guest_debug_println!("handling a signal from the kernel thread");
            // This signal is sent by the kernel thread. Ignore the current context,
            // and instead handle the pending signals.
            maybe_handle_pending_signals(global_state, &thread_state.sig_mask);
            return;
        }
    }

    let mask = &thread_state.sig_mask;
    if signals::sigismember(mask, sig) {
        if synchronous_signal(sig) {
            // If a synchronous signal is blocked, the kernel will kill the process.
            guest_debug_println!(
                "synchronous signal {} is blocked in this thread. aborting the process",
                signals::sig_to_string(sig)
            );
            signals::sig_abort(sig);
        }
        // This case, the signal is blocked in this thread and is not either thread-direct or synchronous.
        guest_debug_println!(
            "signal {} is blocked in this thread. adding it to the pending signals",
            signals::sig_to_string(sig)
        );
        global_state.add_global_pending_signal(sig, info, ucontext);
    } else {
        let global_state = unsafe { &*get_global_state(sp) };
        let action = global_state.sigaction_read(sig);
        // TODO:
        //  Any signals specified in act->sa_mask when registering the handler
        //  with sigprocmask(2) are added to the thread's signal mask.
        invoke_sigaction(sig, &action, info, ucontext);
    }
}

pub fn handle_syscall(info: &siginfo_t, ucontext: &mut ucontext_t) {
    let sp = ucontext.uc_stack.stack_end();

    let sys_no = syscalls::Sysno::from(ucontext.syscall_no() as i32);
    let sig_data = unsafe { &mut *get_sig_data(sp) };
    // Prepare the sig_data so that the kernel can access it.
    sig_data.set(
        info,
        ucontext,
        if sys_no == Sysno::clone {
            sys::__get_tp()
        } else {
            0
        },
    );

    let thread_state = unsafe { &mut *get_child_thread_state_ptr(sp) };
    let global_state = get_global_state(sp);

    guest_debug_println!("syscall {}", sys_no);
    match sys_no {
        Sysno::rt_sigaction => {
            handle_sigaction(global_state, sig_data);
        }
        Sysno::rt_sigprocmask => {
            let current_mask = &mut thread_state.sig_mask;
            handle_sigprocmask(current_mask, sig_data);

            // After update the signal mask, check pending signals from the kernel.
            sig_data.info = core::ptr::null(); // Indicate that this wakeup is not for a syscall.
            let thread_sync = get_thread_sync(sp);
            let thread_sync = unsafe { &mut *thread_sync };
            guest_debug_println!("wake up the kernel to check pending signals");
            thread_sync.child_exit();
            guest_debug_println!("woke up the kernel. waiting for the kernel to wake me up");
            thread_sync.child_enter();
            guest_debug_println!("woken up by the kernel");
        }
        Sysno::sigaltstack => {
            handle_sigaltstack(sp, sig_data);
        }
        _ => {
            let thread_sync = get_thread_sync(sp);
            let thread_sync = unsafe { &mut *thread_sync };

            guest_debug_println!("wake up the kernel to handle {}", sys_no);
            thread_sync.child_exit();
            guest_debug_println!("woke up the kernel. waiting for the kernel to wake me up");
            thread_sync.child_enter();
            guest_debug_println!("woken up by the kernel");
        }
    }
    guest_debug_println!(
        "syscall {} done: {}",
        sys_no,
        sig_data.ucontext().syscall_ret()
    );
}

fn maybe_handle_pending_signals(global_state: *mut GlobalState, thread_mask: &SigSet) {
    // TODO: add thread-directed signal handling.
    guest_debug_println!("handling pending signals");
    let global_state = unsafe { &mut *global_state };
    let candidate_signals = global_state.pending_signal_handling_candidates(thread_mask);
    if candidate_signals == 0 {
        guest_debug_println!("no pending signals");
        return;
    }

    guest_debug_println!(
        "pending signals: {}",
        signals::sigmask_to_string(candidate_signals)
    );

    for signum in 1..=64 {
        if signals::sigismember(&candidate_signals, signum) {
            if let Some(mut pending_signal) = global_state.get_global_pending_signal(signum) {
                let action = global_state.sigaction_read(signum);
                invoke_sigaction(
                    signum,
                    &action,
                    &pending_signal.info,
                    &mut pending_signal.uc,
                );
            }
        }
    }
}

fn invoke_sigaction(sig: usize, action: &SigAction, info: &siginfo_t, ucontext: &mut ucontext_t) {
    guest_debug_println!("invoke_sigaction: sig = {}", signals::sig_to_string(sig));
    match action.sa_sigaction as usize {
        sys::SIG_DFL => {
            guest_debug_println!(
                "handle default signal action for {}",
                signals::sig_to_string(sig)
            );
            signals::do_default_sigaction(sig);
        }
        sys::SIG_IGN => {
            guest_debug_println!("ignore signal {}", signals::sig_to_string(sig));
        }
        _ => {
            // TODO: execute the signal handler in a user defined stack if present,
            //  though not sure if that's possible at all since we have to allow nested signal
            //  handling for SIGSYS to enable syscalls in a user-defined signal handler.
            guest_debug_println!("executing the signal handler {:p}", action.sa_sigaction);
            let handler = unsafe {
                // Regardless whether it is sa_handler or sa_sigaction, we invoke it as a sa_sigaction where
                // two additional arguments are passed. That might waste two registers but that
                // should be negligible.
                core::mem::transmute::<*mut u8, extern "C" fn(i32, *const siginfo_t, *mut ucontext_t)>(
                    action.sa_sigaction,
                )
            };
            handler(sig as i32, info, ucontext);
            guest_debug_println!("exec_sig_handler returned");
        }
    }
}

fn get_thread_sync(sp: *mut u8) -> *mut ThreadSync {
    unsafe { *(sp.offset(THREAD_SYNC_OFFSET) as *mut *mut ThreadSync) }
}

fn set_thread_sync(sp: *mut u8, thread_sync: *mut ThreadSync) {
    unsafe {
        *(sp.offset(THREAD_SYNC_OFFSET) as *mut *mut ThreadSync) = thread_sync;
    }
}

fn get_global_state(sp: *mut u8) -> *mut GlobalState {
    unsafe { *(sp.offset(GLOBAL_STATE_OFFSET) as *mut *mut GlobalState) }
}

fn set_global_state(sp: *mut u8, global_state: *mut GlobalState) {
    unsafe {
        *(sp.offset(GLOBAL_STATE_OFFSET) as *mut *mut GlobalState) = global_state;
    }
}

fn get_sig_data(sp: *mut u8) -> *mut SigData {
    unsafe { *(sp.offset(SIG_DATA_OFFSET) as *mut *mut SigData) }
}

fn set_sig_data(sp: *mut u8, sig_data: *mut SigData) {
    unsafe {
        *(sp.offset(SIG_DATA_OFFSET) as *mut *mut SigData) = sig_data;
    }
}

fn get_sigaltstack(sp: *mut u8) -> (*mut u8, usize) {
    unsafe { *(sp.offset(SIG_ALTSTACK_OFFSET) as *mut (*mut u8, usize)) }
}

fn set_sigaltstack(sp: *mut u8, sigaltstack: *mut u8, size: usize) {
    unsafe {
        *(sp.offset(SIG_ALTSTACK_OFFSET) as *mut (*mut u8, usize)) = (sigaltstack, size);
    }
}

fn get_child_thread_state_ptr(sp: *mut u8) -> *mut ChildThreadState {
    unsafe { *(sp.offset(THREAD_STATE_PTR_OFFSET) as *mut *mut ChildThreadState) }
}

fn set_child_thread_state_ptr(sp: *mut u8, thread_state: *mut ChildThreadState) {
    unsafe {
        *(sp.offset(THREAD_STATE_PTR_OFFSET) as *mut *mut ChildThreadState) = thread_state;
    }
}

fn set_kernel_thread_id(sp: *mut u8, kernel_thread_id: usize) {
    unsafe {
        *(sp.offset(KERNEL_THREAD_ID_OFFSET) as *mut usize) = kernel_thread_id;
    }
}

fn get_kernel_thread_id(sp: *mut u8) -> usize {
    unsafe { *(sp.offset(KERNEL_THREAD_ID_OFFSET) as *mut usize) }
}

fn handle_sigaction(global_state: *mut GlobalState, sig_data: *mut SigData) {
    let (global_state, sig_data) = unsafe { (&mut *global_state, &mut *sig_data) };
    let ucontext = sig_data.ucontext();
    let (signum, new_ptr, old_ptr, _sa_mask_size) = ucontext.syscall_arg4();
    let ret = handle_sigaction_impl(global_state, signum, new_ptr, old_ptr);
    ucontext.set_syscall_ret(ret);
}

fn handle_sigaction_impl(
    global_state: &mut GlobalState,
    signum: usize,
    new_ptr: usize,
    old_ptr: usize,
) -> usize {
    match signum {
        signals::SIGSYS => {
            guest_debug_println!(
                "rt_sigaction: setting a signal handler for SIGSYS is forbidden by tvisor"
            );
            -sys::EINVAL as usize
        }
        _ => {
            guest_debug_println!("rt_sigaction: signum = {}", signum);
            let mut action = global_state.sigaction_write(signum);
            if old_ptr != 0 {
                let old = unsafe { &mut *(old_ptr as *mut SigAction) };
                *old = *action;
            }
            if new_ptr != 0 {
                let new = unsafe { &*(new_ptr as *const SigAction) };
                *action = *new;
            }
            0
        }
    }
}

fn handle_sigprocmask(current_mask: &mut SigSet, sig_data: *mut SigData) {
    let sig_data = unsafe { &mut *sig_data };
    let ucontext = sig_data.ucontext();

    let (how, set_ptr, oldset_ptr, _sigset_size) = ucontext.syscall_arg4();
    guest_debug_println!(
        "rt_sigprocmask: how = {}, set_ptr = {}, oldset_ptr = {:#x} / current_mask = {}",
        sys::sigprocmask_how_to_str(how as i32),
        if set_ptr == 0 {
            "EMPTY".to_string()
        } else {
            let new = unsafe { &*(set_ptr as *const SigSet) };
            signals::sigmask_to_string(*new).to_string()
        },
        oldset_ptr,
        signals::sigmask_to_string(*current_mask)
    );
    let ret = handle_sigprocmask_impl(current_mask, how as i32, set_ptr, oldset_ptr);
    ucontext.set_syscall_ret(ret as usize);
    guest_debug_println!(
        "rt_sigprocmask: updated_current_mask = {}",
        signals::sigmask_to_string(*current_mask)
    );
}

fn handle_sigprocmask_impl(mask_ptr: &mut SigSet, how: i32, new_ptr: usize, old_ptr: usize) -> i32 {
    if old_ptr != 0 {
        let old = unsafe { &mut *(old_ptr as *mut SigSet) };
        *old = *mask_ptr;
    }

    if new_ptr == 0 {
        return 0;
    }

    let new = unsafe { &*(new_ptr as *const SigSet) };
    match how {
        sys::SIG_BLOCK => {
            for signum in 1..=64 {
                if signals::sigismember(new, signum) {
                    signals::sigaddset(mask_ptr, signum);
                }
            }
        }
        sys::SIG_UNBLOCK => {
            for signum in 1..=64 {
                if signals::sigismember(new, signum) {
                    signals::sigdelset(mask_ptr, signum);
                }
            }
        }
        sys::SIG_SETMASK => {
            *mask_ptr = *new;
        }
        _ => {
            return -sys::EINVAL;
        }
    }
    0
}

fn handle_sigaltstack(sp: *mut u8, sig_data: &mut SigData) {
    let ucontext = sig_data.ucontext();
    let (ss, old_ss) = ucontext.syscall_arg2();
    let ret = handle_sigaltstack_impl(sp, ss, old_ss);
    ucontext.set_syscall_ret(ret as usize);
}

fn handle_sigaltstack_impl(sp: *mut u8, ss: usize, old_ss: usize) -> i32 {
    if old_ss != 0 {
        // TODO: SS_AUTODISARM.
        let old = unsafe { &mut *(old_ss as *mut stack_t) };
        let (alt_ptr, size) = get_sigaltstack(sp);
        if alt_ptr.is_null() {
            old.ss_flags = sys::SS_DISABLE;
            old.ss_sp = core::ptr::null_mut();
            old.ss_size = 0;
            guest_debug_println!("old.ss_flags = SS_DISABLE; old.ss_sp = null");
        } else {
            old.ss_flags = sys::SS_ONSTACK;
            old.ss_sp = alt_ptr;
            old.ss_size = size;
            guest_debug_println!(
                "old.ss_flags = SS_ONSTACK; old.ss_sp = {:#x}; old.ss_size = {:#x}",
                old.ss_sp as usize,
                old.ss_size
            );
        }
    }
    if ss != 0 {
        // TODO: SS_AUTODISARM.
        let new = unsafe { &*(ss as *mut stack_t) };
        set_sigaltstack(sp, new.ss_sp, new.ss_size);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_case;

    test_case!(test_get_thread_sync, {
        let mut thread_sync = ThreadSync::new();
        let mut stack = [0u8; SIGNAL_STACK_SIZE + STACK_DATA_TOTAL_SIZE];
        let sp = stack.as_mut_ptr();
        set_thread_sync(sp, &mut thread_sync);
        let actual_thread_sync = get_thread_sync(sp);
        assert_eq!(actual_thread_sync, &mut thread_sync as *mut ThreadSync);
    });

    test_case!(test_get_set_global_state, {
        let mut global_state = GlobalState::new();
        let mut stack = [0u8; SIGNAL_STACK_SIZE + STACK_DATA_TOTAL_SIZE];
        let sp = stack.as_mut_ptr();
        set_global_state(sp, &mut global_state);
        let actual_global_state = get_global_state(sp);
        assert_eq!(actual_global_state, &mut global_state as *mut GlobalState);
    });

    test_case!(test_get_set_sig_data, {
        let mut sig_data = SigData::default();
        let mut stack = [0u8; SIGNAL_STACK_SIZE + STACK_DATA_TOTAL_SIZE];
        let sp = stack.as_mut_ptr();
        set_sig_data(sp, &mut sig_data);
        let actual_sig_data = get_sig_data(sp);
        assert_eq!(actual_sig_data, &mut sig_data as *mut SigData);
    });

    test_case!(test_get_set_child_thread_state, {
        let mut thread_state = ChildThreadState::new(0);
        let mut stack = [0u8; SIGNAL_STACK_SIZE + STACK_DATA_TOTAL_SIZE];
        let sp = stack.as_mut_ptr();
        set_child_thread_state_ptr(sp, &mut thread_state);
        let actual_thread_state = get_child_thread_state_ptr(sp);
        assert_eq!(
            actual_thread_state,
            &mut thread_state as *mut ChildThreadState
        );
    });

    test_case!(test_handle_sigaction_impl, {
        let mut global_state = GlobalState::new();
        // new,old == null.
        let ret = handle_sigaction_impl(&mut global_state, signals::SIGUSR1, 0, 0);
        assert_eq!(ret, 0);

        // Set new.
        extern "C" fn tmp(_: i32, _: &siginfo_t, _: &mut ucontext_t) {}
        let new = sys::SigAction {
            sa_sigaction: tmp as *mut u8,
            sa_flags: 1,
            _sa_restorer: 2,
            sa_mask: 3,
        };
        let ret = handle_sigaction_impl(
            &mut global_state,
            signals::SIGUSR1,
            &new as *const SigAction as usize,
            0,
        );
        assert_eq!(ret, 0);
        {
            let action = global_state.sigaction_write(signals::SIGUSR1);
            assert_eq!(action.sa_sigaction, tmp as *mut u8);
            assert_eq!(action.sa_flags, 1);
            assert_eq!(action._sa_restorer, 2);
            assert_eq!(action.sa_mask, 3);
        }

        // Get old.
        let mut old = SigAction::default();
        let ret = handle_sigaction_impl(
            &mut global_state,
            signals::SIGUSR1,
            0,
            &mut old as *mut SigAction as usize,
        );
        assert_eq!(ret, 0);
        assert_eq!(old.sa_sigaction, tmp as *mut u8);
        assert_eq!(old.sa_flags, 1);
        assert_eq!(old._sa_restorer, 2);
        assert_eq!(old.sa_mask, 3);
    });

    test_case!(test_get_set_kernel_thread_id, {
        let mut stack = [0u8; SIGNAL_STACK_SIZE + STACK_DATA_TOTAL_SIZE];
        let sp = stack.as_mut_ptr();
        set_kernel_thread_id(sp, 123);
        let actual_kernel_thread_id = get_kernel_thread_id(sp);
        assert_eq!(actual_kernel_thread_id, 123);
    });

    test_case!(test_handle_sigprocmask_impl, {
        let mut mask = SigSet::default();
        signals::sigaddset(&mut mask, signals::SIGUSR1);
        signals::sigaddset(&mut mask, signals::SIGUSR2);
        signals::sigaddset(&mut mask, signals::SIGSYS);
        let ret = handle_sigprocmask_impl(&mut mask, sys::SIG_BLOCK, 0, 0);
        assert_eq!(ret, 0);

        let old_mask = SigSet::default();
        let ret = handle_sigprocmask_impl(
            &mut mask,
            sys::SIG_SETMASK,
            0,
            &old_mask as *const SigSet as usize,
        );
        assert_eq!(ret, 0);
        assert_eq!(old_mask, mask);

        let mut new_mask = SigSet::default();
        signals::sigaddset(&mut new_mask, signals::SIGUSR1);
        signals::sigaddset(&mut new_mask, signals::SIGTRAP);
        let ret = handle_sigprocmask_impl(
            &mut mask,
            sys::SIG_SETMASK,
            &new_mask as *const SigSet as usize,
            0,
        );
        assert_eq!(ret, 0);
        assert_eq!(mask, new_mask);
        assert!(signals::sigismember(&mask, signals::SIGUSR1));
        assert!(signals::sigismember(&mask, signals::SIGTRAP));

        let mut block_mask = SigSet::default();
        signals::sigaddset(&mut block_mask, signals::SIGABRT);
        let ret = handle_sigprocmask_impl(
            &mut mask,
            sys::SIG_BLOCK,
            &block_mask as *const SigSet as usize,
            0,
        );
        assert_eq!(ret, 0);
        assert!(signals::sigismember(&mask, signals::SIGABRT));
        assert!(signals::sigismember(&mask, signals::SIGUSR1));
        assert!(signals::sigismember(&mask, signals::SIGTRAP));

        let mut unblock_mask = SigSet::default();
        signals::sigaddset(&mut unblock_mask, signals::SIGUSR1);
        let ret = handle_sigprocmask_impl(
            &mut mask,
            sys::SIG_UNBLOCK,
            &unblock_mask as *const SigSet as usize,
            0,
        );
        assert_eq!(ret, 0);
        assert!(!signals::sigismember(&mask, signals::SIGUSR1));
        assert!(signals::sigismember(&mask, signals::SIGABRT));
        assert!(signals::sigismember(&mask, signals::SIGTRAP));
    });

    test_case!(test_handle_sigaltstack_impl, {
        let mut stack = [0u8; STACK_DATA_TOTAL_SIZE];
        let sp = stack.as_mut_ptr();
        let ret = handle_sigaltstack_impl(sp, 0, 0);
        assert_eq!(ret, 0);
        let (actual_ss, _) = get_sigaltstack(sp);
        assert_eq!(actual_ss as usize, 0);

        let mut ss = stack_t::default();
        ss.ss_sp = 0x1000 as *mut u8;
        ss.ss_size = 0x2000;
        let ret = handle_sigaltstack_impl(sp, &ss as *const stack_t as usize, 0);
        assert_eq!(ret, 0);
        let (actual_ss, size) = get_sigaltstack(sp);
        assert_eq!(actual_ss as usize, ss.ss_sp as usize);
        assert_eq!(size, ss.ss_size);

        let old_ss = stack_t::default();
        let ret = handle_sigaltstack_impl(sp, 0, &old_ss as *const stack_t as usize);
        assert_eq!(ret, 0);
        assert_eq!(old_ss.ss_sp as usize, ss.ss_sp as usize);
        assert_eq!(old_ss.ss_size, ss.ss_size);
    });
}
