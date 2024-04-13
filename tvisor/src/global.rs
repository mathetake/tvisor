use crate::signals;
use crate::signals::SigSet;
use crate::sys::{siginfo_t, ucontext_t, SigAction};
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use spin::rwlock::{RwLock, RwLockReadGuard, RwLockWriteGuard};

#[repr(C)]
pub struct GlobalState {
    sig_actions: [RwLock<SigAction>; 65],
    threads: RwLock<Vec<*mut ChildThreadState>>,
    pending_signals: [RwLock<VecDeque<Box<PendingSignalItem>>>; 65],
    pending_signals_existing_mask: RwLock<SigSet>,
}

#[allow(dead_code)]
pub struct PendingSignalItem {
    pub info: siginfo_t,
    pub uc: ucontext_t,
}

#[repr(C)]
pub struct ChildThreadState {
    pub sig_mask: SigSet,
}

impl GlobalState {
    pub fn new() -> Self {
        Self {
            sig_actions: core::array::from_fn(|_| RwLock::new(SigAction::default())),
            threads: RwLock::new(Vec::new()),
            pending_signals: core::array::from_fn(|_| RwLock::new(VecDeque::new())),
            pending_signals_existing_mask: RwLock::new(0),
        }
    }

    pub fn sigaction_read(&self, sig: usize) -> RwLockReadGuard<'_, SigAction> {
        self.sig_actions[sig].read()
    }

    pub fn sigaction_write(&self, sig: usize) -> RwLockWriteGuard<'_, SigAction> {
        self.sig_actions[sig].write()
    }

    pub fn add_new_child_thread(&mut self, thread_state: *mut ChildThreadState) {
        // TODO: delete when thread exits.
        let mut threads = self.threads.write();
        threads.push(thread_state);
    }

    pub fn add_global_pending_signal(
        &mut self,
        sig: usize,
        info: &siginfo_t,
        ucontext: &mut ucontext_t,
    ) {
        let mut pending_signals = self.pending_signals[sig].write();
        pending_signals.push_back(Box::new(PendingSignalItem {
            info: info.clone(),
            uc: ucontext.clone(),
        }));
        let mut existing_mask = self.pending_signals_existing_mask.write();
        signals::sigaddset(&mut existing_mask, sig);
    }

    pub fn get_global_pending_signal(&mut self, sig: usize) -> Option<Box<PendingSignalItem>> {
        let mut pending_signals = self.pending_signals[sig].write();
        pending_signals.pop_front()
    }

    pub fn pending_signal_handling_candidates(&mut self, thread_mask: &SigSet) -> SigSet {
        // Try to find the intersection of the pending signals and the thread mask.
        // Here we do not take lock on the pending_signals, as we are interested in the "best effort" result.
        let handling_target_mask = *self.pending_signals_existing_mask.get_mut();
        handling_target_mask & !(*thread_mask)
    }
}

impl ChildThreadState {
    pub fn new(sig_mask: SigSet) -> Self {
        Self { sig_mask }
    }
}

impl Default for GlobalState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_case;

    test_case!(test_add_global_pending_signal, {
        let mut global_state = GlobalState::new();
        let sig = 1;
        let mut info = siginfo_t::default();
        info.si_signo = sig as i32;
        let mut ucontext = ucontext_t::default();
        global_state.add_global_pending_signal(sig, &info, &mut ucontext);
        let pending_signals = global_state.pending_signals[sig].read();
        assert_eq!(pending_signals.len(), 1);
        assert_eq!(pending_signals[0].info, info);
        assert_eq!(pending_signals[0].uc, ucontext);
        drop(pending_signals);

        // Test adding another signal.
        let sig = 2;
        let mut info = siginfo_t::default();
        info.si_signo = sig as i32;
        let mut ucontext = ucontext_t::default();
        ucontext.uc_flags = 1;
        global_state.add_global_pending_signal(sig, &info, &mut ucontext);
        let pending_signals = global_state.pending_signals[sig].read();
        assert_eq!(pending_signals.len(), 1);
        assert_eq!(pending_signals[0].info, info);
        assert_eq!(pending_signals[0].uc, ucontext);
    });

    test_case!(test_get_global_pending_signal, {
        let mut global_state = GlobalState::new();
        let sig = 1;
        let mut info = siginfo_t::default();
        info.si_signo = sig as i32;
        let mut ucontext = ucontext_t::default();
        global_state.add_global_pending_signal(sig, &info, &mut ucontext);
        let pending_signals = global_state.pending_signals[sig].read();
        assert_eq!(pending_signals.len(), 1);
        drop(pending_signals);

        let pending_signal = global_state.get_global_pending_signal(sig);
        assert!(pending_signal.is_some());
        assert_eq!(pending_signal.unwrap().info, info);

        let pending_signals = global_state.pending_signals[sig].read();
        assert_eq!(pending_signals.len(), 0);
    });
}
