extern crate alloc;
use talc::*;

use core::fmt;
use core::fmt::Write;
use core::panic::PanicInfo;
use core::ptr::addr_of_mut;
use syscalls::*;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    if let Some(location) = info.location() {
        let mut stderr = Stderr;
        writeln!(
            stderr,
            "panicked at {}:{}",
            location.file(),
            location.line()
        )
        .unwrap();
    }

    if let Some(msg) = info.message() {
        let mut stderr = Stderr;
        stderr.write_fmt(*msg).unwrap();
    }

    emit_byte_stderr(b'\n');
    abort(1)
}

#[macro_export]
macro_rules! debug_print {
    ($($arg:tt)*) => {
        if cfg!(debug_assertions) {
            $crate::print!($($arg)*);
        }
    };
}

#[macro_export]
macro_rules! debug_println {
    ($($arg:tt)*) => {
        if cfg!(debug_assertions) {
            $crate::println!($($arg)*);
        }
    };
}

#[macro_export]
macro_rules! kernel_debug_println {
    ($($arg:tt)*) => {
        debug_println!("\x1b[31m[kernel pid={}/tid={}]\x1b[0m {}", sys::getpid(), sys::gettid(), format_args!($($arg)*));
    }
}

#[macro_export]
macro_rules! guest_debug_println {
    ($($arg:tt)*) => {
        debug_println!("\x1b[32m[guest pid={}/tid={}]\x1b[0m {}", sys::getpid(), sys::gettid(), format_args!($($arg)*));
    }
}

#[macro_export]
macro_rules! kernel_panic {
    ($($arg:tt)*) => {
        panic!("\x1b[31m[kernel pid={}/tid={}]\x1b[0m {}", sys::getpid(), sys::gettid(), format_args!($($arg)*));
    }
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::rt::_print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}

#[macro_export]
macro_rules! print_stdout {
    ($($arg:tt)*) => ($crate::rt::_print_stdout(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! println_stdout {
    () => ($crate::print_stdout!("\n"));
    ($($arg:tt)*) => ($crate::print_stdout!("{}\n", format_args!($($arg)*)));
}

pub fn _print(args: fmt::Arguments) {
    let mut stdout = Stderr;
    stdout.write_fmt(args).unwrap();
}

pub fn _print_stdout(args: fmt::Arguments) {
    let mut stdout = Stdout;
    stdout.write_fmt(args).unwrap();
}

struct Stderr;

impl Write for Stderr {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        emit_bytes(2, s.as_bytes());
        Ok(())
    }
}

struct Stdout;

impl Write for Stdout {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        emit_bytes(1, s.as_bytes());
        Ok(())
    }
}

fn emit_byte_stderr(byte: u8) {
    let stderr_fd = 2;
    let buffer = [byte];

    unsafe {
        match syscall!(Sysno::write, stderr_fd, buffer.as_ptr(), buffer.len()) {
            Ok(_) => {}
            Err(err) => panic!("Failed to write byte: {}", err),
        }
    }
}

fn emit_bytes(fd: i32, bytes: &[u8]) {
    unsafe {
        match syscall!(Sysno::write, fd, bytes.as_ptr(), bytes.len()) {
            Ok(_) => {}
            Err(err) => panic!("Failed to write bytes: {}", err),
        }
    }
}

#[allow(clippy::empty_loop)]
pub fn abort(code: i32) -> ! {
    unsafe {
        let _ = syscall!(Sysno::exit_group, code);
    }
    loop {}
}

// TODO: Make the size of the arena configurable.
static mut ARENA: [u8; 100000] = [0; 100000];

#[global_allocator]
static ALLOCATOR: Talck<spin::Mutex<()>, ClaimOnOom> = Talc::new(unsafe {
    // if we're in a hosted environment, the Rust runtime may allocate before
    // main() is called, so we need to initialize the arena automatically
    ClaimOnOom::new(Span::from_array(addr_of_mut!(ARENA)))
})
.lock();
