use core::hint::spin_loop;
use core::sync::atomic::Ordering;
use syscalls::{syscall, Sysno};

const FUTEX_WAIT: u32 = 0;
const FUTEX_WAKE: u32 = 1;

#[repr(C)]
pub struct ThreadSync {
    turn: portable_atomic::AtomicI32,
}

const THREAD_SYNC_TURN_PARENT: i32 = 1;
const THREAD_SYNC_TURN_CHILD: i32 = 2;

impl ThreadSync {
    pub fn new() -> Self {
        Self {
            turn: portable_atomic::AtomicI32::new(THREAD_SYNC_TURN_CHILD),
        }
    }

    pub fn parent_enter(&mut self) {
        self.wait_for_turn(THREAD_SYNC_TURN_PARENT);
    }

    pub fn parent_exit(&mut self) {
        self.signal_turn(THREAD_SYNC_TURN_CHILD);
    }

    pub fn child_enter(&mut self) {
        self.wait_for_turn(THREAD_SYNC_TURN_CHILD);
    }

    pub fn child_exit(&mut self) {
        self.signal_turn(THREAD_SYNC_TURN_PARENT);
    }

    fn wait_for_turn(&mut self, expected_val: i32) {
        let mut spin_count = 0;
        loop {
            let current_val = self.turn.load(Ordering::Relaxed);
            if current_val == expected_val {
                break;
            }

            if spin_count < 10 {
                spin_loop();
                spin_count += 1;
            } else {
                let ptr = self.turn.as_ptr();
                unsafe {
                    let _ = syscall!(Sysno::futex, ptr, FUTEX_WAIT, current_val, 0, 0, 0);
                }
            }
        }
    }

    fn signal_turn(&mut self, new_val: i32) {
        self.turn.store(new_val, Ordering::Relaxed);
        let ptr = self.turn.as_ptr();
        unsafe {
            syscall!(Sysno::futex, ptr, FUTEX_WAKE, 1, 0, 0, 0).unwrap();
        }
    }
}

impl Default for ThreadSync {
    fn default() -> Self {
        Self::new()
    }
}
