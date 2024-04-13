#![no_main]
#![no_std]
#![feature(custom_test_frameworks)]
#![test_runner(test_runner)]
#![reexport_test_harness_main = "test_main"]

use core::fmt::Debug;
use syscalls::Sysno;
use tvisor::sys::ucontext_t;
use tvisor::Kernel;
use tvisor::{define_main, println_stdout};

define_main!(NopKernel);

#[derive(Debug, Default, Clone)]
struct NopKernel {}

impl Kernel for NopKernel {
    fn syscall_nos() -> &'static [Sysno] {
        &[Sysno::getuid]
    }

    fn help() {
        println_stdout!("tvisor-nop: does nothing")
    }

    fn getuid(&mut self, ucontext: &mut ucontext_t) {
        ucontext.set_syscall_ret(unsafe { UID });
        unsafe { UID += 9999 };
    }
}

static mut UID: usize = 9999;
