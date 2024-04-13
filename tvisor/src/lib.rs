#![no_std]
#![no_main]
#![feature(panic_info_message)]
#![feature(custom_test_frameworks)]
#![test_runner(test_runner)]
#![reexport_test_harness_main = "test_main"]
#![feature(const_mut_refs)]

#[allow(unused_imports)]
#[macro_use]
extern crate alloc;

pub mod kernel;
pub mod rt;
pub mod sys;

use alloc::boxed::Box;
pub use kernel::Kernel;

mod bpf;
mod global;
mod guest;
mod loader;
mod signals;
mod sync;
mod util;

pub const PAGE_SIZE: usize = 4096; // TODO: revisit.
pub const STACK_SIZE: usize = 0x200000; // TODO: revisit.

#[macro_export]
/// Define the main function for the kernel.
/// The user crate must define following crate attributes to use this macro:
/// ```
/// #![no_main]
/// #![no_std]
/// #![feature(custom_test_frameworks)]
/// #![test_runner(test_runner)]
/// #![reexport_test_harness_main = "test_main"]
/// ```
///
/// And the parameter type must implement the `Kernel` trait.
macro_rules! define_main {
    ($t:ty) => {
        #[cfg(not(test))]
        #[allow(clippy::missing_safety_doc)]
        #[no_mangle]
        pub unsafe extern "C" fn rust_start(stack_ptr: *const *const u8) -> ! {
            tvisor::__main::<$t>(stack_ptr)
        }

        #[cfg(test)]
        #[no_mangle]
        pub extern "C" fn rust_start(_stack_ptr: *const *const u8) -> ! {
            test_main();
            tvisor::sys::exit_group(0);
        }

        #[cfg(test)]
        fn test_runner(tests: &[&dyn Fn()]) {
            tvisor::debug_println!("\nRunning {} tests\n", tests.len());
            for test in tests {
                test();
            }
            tvisor::debug_println!("\n{} tests passed\n", tests.len());
        }

        #[no_mangle]
        unsafe extern "C" fn cloned_kernel_main(raw_clone_guest_args: *mut u8) -> ! {
            tvisor::kernel::KernelThread::<$t>::cloned_kernel_main(raw_clone_guest_args);
        }
    };
}

pub static mut ORIGINAL_ARGV: *const *const u8 = core::ptr::null();

#[allow(clippy::missing_safety_doc)]
pub unsafe fn __main<T: Kernel>(stack_ptr: *const *const u8) -> ! {
    let kernel = Box::leak(Box::<T>::default());

    // Set the no new privs flag to be able to use seccomp.
    sys::no_new_prev();

    let argc = *stack_ptr as isize;
    let argv = stack_ptr.offset(1);
    ORIGINAL_ARGV = argv; // This will be used by execve handler.

    if argc < 2 {
        T::help();
        sys::exit_group(0)
    }
    let mut arg_iter = ArgsIter::<T>::new(argv);
    kernel.init(&mut arg_iter);
    arg_iter.ensure_at_dashdash();
    let guest_args_begin = arg_iter.cur;
    let guest_argc = argc - guest_args_begin;

    // Read the program name.
    let program_name = {
        let raw_name = *argv.offset(guest_args_begin);
        util::cstr_from_ptr(raw_name)
    };

    let mut loader = loader::Loader::new();
    let entry_point = loader.load_from_file(program_name);
    let phdr = loader.phdr();

    // Then allocate the stack for the main thread with the additional space for the guard page.
    let stack_size = STACK_SIZE + PAGE_SIZE;
    let stack_bottom = sys::mmap(
        0,
        stack_size,
        sys::PROT_READ | sys::PROT_WRITE,
        sys::MAP_PRIVATE | sys::MAP_ANONYMOUS,
    );
    // And set the guard page.
    sys::mprotect(stack_bottom, PAGE_SIZE, sys::PROT_NONE);

    let stack_top = initialize_stack(
        stack_bottom,
        stack_size,
        guest_argc,
        argv.offset(guest_args_begin),
        phdr,
    );

    debug_println!("--- start ---");
    debug_println!("entry point = {:?}", entry_point);
    debug_println!("stack top = {:#x}", stack_top);
    debug_println!("stack bottom = {:#x}", stack_bottom as usize);
    debug_println!("stack size = {:#x}", stack_size);

    let global_state = Box::into_raw(Box::new(global::GlobalState::new()));
    signals::init();
    let clone_guest_args = kernel::CloneGuestArgs {
        guest_entrypoint: entry_point,
        guest_child_stack: stack_top as *mut u8,
        // The main thread's tls will be retrieved from the auxv.
        guest_tls: core::ptr::null_mut(),
        guest_ctid: 0,
        guest_ptid: 0,
        raw_child_guest_thread_id_ptr: core::ptr::null_mut(),
        raw_parent_kernel_sync: core::ptr::null_mut(),
        mcontext: core::ptr::null_mut(),
        global_state,
    };
    kernel::KernelThread::start(kernel, &clone_guest_args);
}

unsafe fn initialize_stack(
    stack_bottom: *mut u8,
    stack_size: usize,
    argc: isize,
    argv: *const *const u8,
    phdr: (usize, usize, usize),
) -> usize {
    let stack_size = stack_size - 16; // Adjust for alignment.

    // Walk through argv to find the end, then environment variables start.
    // --- arguments ---
    let mut stack_argument_size = 8; // argc
    stack_argument_size += (argc + 1) * 8;

    // --- environment variables ---
    let mut envp_tmp = argv.add(argc as usize + 1);
    let envp = envp_tmp;
    let mut envc = 0;
    while !(*envp_tmp).is_null() {
        envc += 1;
        envp_tmp = envp_tmp.add(1);
    }
    stack_argument_size += (envc + 1) * 8;
    let auxv = envp_tmp.add(1) as *const (i64, i64);

    // --- auxv ---
    // https://articles.manugarg.com/aboutelfauxiliaryvectors
    // https://docs.rs/auxv/latest/auxv/
    // https://codebrowser.dev/glibc/glibc/sysdeps/unix/sysv/linux/dl-parse_auxv.h.html#_dl_parse_auxv
    // https://github.com/torvalds/linux/blob/bfa76d49576599a4b9f9b7a71f23d73d6dcff735/include/uapi/linux/auxvec.h#L12
    const AT_NULL: i64 = 0;
    const AT_PHDR: i64 = 3;
    const AT_PHENT: i64 = 4;
    const AT_PHNUM: i64 = 5;
    for i in 0.. {
        let (key, _) = *auxv.offset(i);
        stack_argument_size += 16;
        if key == AT_NULL {
            break;
        }
    }

    // Now advance the stack pointer to the bottom of the stack.
    let mut cur = stack_bottom as usize + stack_size - stack_argument_size as usize - 16;
    // Align to 16 bytes.
    cur &= !15;
    let sp = cur;

    // Write argc.
    core::ptr::write_volatile(cur as *mut usize, argc as usize);
    cur += 8;
    // Write argv.
    for i in 0..argc {
        let arg = *argv.offset(i);
        core::ptr::write_volatile(cur as *mut usize, arg as usize);
        cur += 8;
    }
    cur += 8;
    // Write envp.
    for i in 0..envc {
        let env = *envp.offset(i);
        core::ptr::write_volatile(cur as *mut usize, env as usize);
        cur += 8;
    }
    cur += 8;

    for i in 0.. {
        let (key, value) = *auxv.offset(i);
        // See:
        //  * https://github.com/google/gvisor/blob/a9bdef23522b5a2ff2a7ec07c3e0573885b46ecb/pkg/sentry/loader/elf.go#L549-L553
        //  * https://github.com/google/gvisor/blob/a9bdef23522b5a2ff2a7ec07c3e0573885b46ecb/pkg/sentry/loader/elf.go#L680-L686
        //  * https://github.com/bminor/musl/blob/f314e133929b6379eccc632bef32eaebb66a7335/src/env/__init_tls.c#L90-L103
        match key {
            AT_PHDR => {
                core::ptr::write_volatile(cur as *mut (i64, i64), (key, phdr.0 as i64));
            }
            AT_PHENT => {
                core::ptr::write_volatile(cur as *mut (i64, i64), (key, phdr.1 as i64));
            }
            AT_PHNUM => {
                core::ptr::write_volatile(cur as *mut (i64, i64), (key, phdr.2 as i64));
            }
            _ => {
                core::ptr::write_volatile(cur as *mut (i64, i64), (key, value));
            }
        }

        cur += 16;
        if key == AT_NULL {
            break;
        }
    }
    sp
}

pub struct ArgsIter<'a, T: Kernel> {
    argv: *const *const u8,
    cur: isize,
    _phantom: core::marker::PhantomData<&'a T>,
}

impl<'a, T: Kernel> ArgsIter<'a, T> {
    fn new(argv: *const *const u8) -> Self {
        ArgsIter {
            argv,
            cur: 1,
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<'a, T: Kernel> Iterator for ArgsIter<'a, T> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        let ptr = unsafe { *self.argv.offset(self.cur) };
        if ptr.is_null() {
            T::help();
            sys::exit_group(1)
        }

        let arg = util::cstr_from_ptr(ptr);
        self.cur += 1;
        if arg == "--" {
            return None;
        }
        Some(arg)
    }
}

impl<'a, T: Kernel> ArgsIter<'a, T> {
    pub fn next_or_exit(&mut self) -> <ArgsIter<'a, T> as Iterator>::Item {
        self.next().unwrap_or_else(|| {
            T::help();
            sys::exit_group(1)
        })
    }

    fn ensure_at_dashdash(&mut self) {
        let ptr = unsafe { *self.argv.offset(self.cur - 1) };
        if ptr.is_null() {
            T::help();
            sys::exit_group(1)
        }
        let arg = util::cstr_from_ptr(ptr);
        if arg != "--" {
            T::help();
            sys::exit_group(1)
        }
    }
}

#[cfg(test)]
#[no_mangle]
pub extern "C" fn rust_start(_stack_ptr: *const *const u8) -> ! {
    test_main();
    sys::exit_group(0);
}

#[cfg(test)]
fn test_runner(tests: &[&dyn Fn()]) {
    debug_println!("\nRunning {} tests\n", tests.len());
    for test in tests {
        test();
    }
    debug_println!("\n{} tests passed\n", tests.len());
}
