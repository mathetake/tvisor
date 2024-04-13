#![no_main]
#![no_std]
#![feature(custom_test_frameworks)]
#![test_runner(test_runner)]
#![reexport_test_harness_main = "test_main"]

use core::fmt::Debug;
use syscalls::raw_syscall;
use syscalls::Sysno;
use tvisor::define_main;
use tvisor::sys::ucontext_t;
use tvisor::Kernel;
use tvisor::{debug_println, println_stdout, sys};

define_main!(FSSandbox);

pub struct FSSandbox {
    path_buf: [u8; 4096],
    root_dir_buf: [u8; 512],
    root_dir_len: usize,
    cwd: [u8; 512],
    cwd_len: usize,
}

impl Default for FSSandbox {
    fn default() -> Self {
        FSSandbox {
            path_buf: [0; 4096],
            root_dir_buf: [0; 512],
            root_dir_len: 0,
            cwd: [0; 512],
            cwd_len: 0,
        }
    }
}

impl Debug for FSSandbox {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FSSandbox")
            .field("root_dir", &unsafe {
                core::str::from_utf8_unchecked(&self.root_dir_buf[0..self.root_dir_len - 1])
            })
            .field("cwd", &unsafe {
                core::str::from_utf8_unchecked(&self.cwd[0..self.cwd_len - 1])
            })
            .finish()
    }
}

impl Clone for FSSandbox {
    fn clone(&self) -> Self {
        Self {
            path_buf: self.path_buf,
            root_dir_buf: self.root_dir_buf,
            root_dir_len: self.root_dir_len,
            cwd: self.cwd,
            cwd_len: self.cwd_len,
        }
    }
}

#[cfg(target_arch = "aarch64")]
static SYSCALL_NOS: &[Sysno] = &[
    Sysno::writev,
    Sysno::openat,
    Sysno::getcwd,
    Sysno::exit_group,
];

#[cfg(target_arch = "x86_64")]
static SYSCALL_NOS: &[Sysno] = &[
    Sysno::writev,
    Sysno::open,
    Sysno::openat,
    Sysno::getcwd,
    Sysno::exit_group,
];

impl Kernel for FSSandbox {
    fn syscall_nos() -> &'static [Sysno] {
        SYSCALL_NOS
    }

    fn help() {
        println_stdout!("tvisor: a Tiny Thread-level syscall monitor on Linux\n");
        println_stdout!("Usage: tvisor [options] -- <program> [args]");
        println_stdout!("Options:");
        println_stdout!(
            "  -c, --cwd <dir>: set the current working directory to <dir>, defaults to /"
        );
        println_stdout!("  -r, --root <dir>: mount the host directory <dir> as the root for the guest, defaults to /");
        println_stdout!("  -h, --help: print this help message");
        println_stdout!();
    }

    fn init(&mut self, args: &mut tvisor::ArgsIter<Self>) {
        let mut root_dir: &str = "/";
        let mut cwd: &str = "/";

        while let Some(arg) = args.next() {
            debug_println!("arg={:?}", arg);
            match arg {
                "-c" | "--cwd" => {
                    cwd = args.next_or_exit();
                }
                "-r" | "--root" => {
                    root_dir = args.next_or_exit();
                }
                "-h" | "--help" => {
                    Self::exit_with_help(0);
                }
                _ => {
                    println_stdout!("Unknown option: {}", arg);
                    Self::exit_with_help(1);
                }
            }
        }

        self.root_dir_len = root_dir.len();
        assert!(self.root_dir_len <= self.root_dir_buf.len());
        self.root_dir_buf[..self.root_dir_len].copy_from_slice(root_dir.as_bytes());
        // Write a null terminator.
        self.root_dir_len += 1;
        self.root_dir_buf[self.root_dir_len] = 0;

        self.cwd_len = cwd.len();
        assert!(self.cwd_len <= self.cwd.len());
        self.cwd[..self.cwd_len].copy_from_slice(cwd.as_bytes());
        // Write a null terminator.
        self.cwd_len += 1;
        self.cwd[self.cwd_len] = 0;
    }

    fn writev(&mut self, ucontext: &mut ucontext_t) {
        let (fd, iov, iovcnt) = ucontext.syscall_arg3();
        let n = unsafe { raw_syscall!(Sysno::writev, fd, iov, iovcnt) };
        ucontext.set_syscall_ret(n)
    }

    #[cfg(target_arch = "x86_64")]
    fn open(&mut self, ucontext: &mut ucontext_t) {
        let (pathname, flags, mode) = ucontext.syscall_arg3();

        let pathname = unsafe {
            let pathname = pathname as *const u8;
            let mut pathname_size = 0;
            while *pathname.add(pathname_size) != 0 {
                pathname_size += 1;
            }
            if pathname_size == 0 {
                todo!("pathname is empty");
            }
            core::slice::from_raw_parts(pathname, pathname_size)
        };

        if pathname[0] != b'/' {
            // Resolve the pathname relative to the current working directory.
            let root_len = self.root_dir_len - 1;
            let cwd_len = self.cwd_len;
            let pathname_len = pathname.len();
            assert!(root_len + cwd_len + pathname_len < self.path_buf.len());
            let mut offset = 0;
            self.path_buf[offset..root_len].copy_from_slice(&self.root_dir_buf[0..root_len]);
            offset += root_len;
            self.path_buf[offset..offset + cwd_len].copy_from_slice(&self.cwd[0..cwd_len]);
            offset += cwd_len;
            self.path_buf[offset - 1] = b'/';
            self.path_buf[offset..offset + pathname_len].copy_from_slice(pathname);
            let a = &self.path_buf[0..offset + pathname_len];
            debug_println!(
                "\x1b[31m[kernel]\x1b[0m open: path={:?}, root={:?}, cwd={:?}",
                unsafe { core::str::from_utf8_unchecked(a) },
                unsafe { core::str::from_utf8_unchecked(&self.root_dir_buf[0..root_len]) },
                unsafe { core::str::from_utf8_unchecked(&self.cwd[0..cwd_len]) },
            );
        } else {
            let root_len = self.root_dir_len - 1;
            let pathname_len = pathname.len();
            assert!(root_len + pathname_len < self.path_buf.len());
            self.path_buf[0..root_len].copy_from_slice(&self.root_dir_buf[0..root_len]);
            self.path_buf[root_len..root_len + pathname_len].copy_from_slice(pathname);
            debug_println!(
                "\x1b[31m[kernel]\x1b[0m open: root_dir={:?} path={:?}",
                unsafe { core::str::from_utf8_unchecked(&self.root_dir_buf[0..root_len]) },
                unsafe {
                    core::str::from_utf8_unchecked(&self.path_buf[0..root_len + pathname_len])
                },
            );
        }

        let fd = unsafe { raw_syscall!(Sysno::open, self.path_buf.as_ptr(), flags, mode) };
        ucontext.set_syscall_ret(fd)
    }

    fn openat(&mut self, ucontext: &mut ucontext_t) {
        let (dirfd, pathname, flags, mode) = ucontext.syscall_arg4();

        if dirfd as i32 != sys::AT_FDCWD {
            todo!("dirfd is not AT_FDCWD");
        }

        let pathname = unsafe {
            let pathname = pathname as *const u8;
            let mut pathname_size = 0;
            while *pathname.add(pathname_size) != 0 {
                pathname_size += 1;
            }
            if pathname_size == 0 {
                todo!("pathname is empty");
            }
            core::slice::from_raw_parts(pathname, pathname_size)
        };

        if pathname[0] != b'/' {
            // Resolve the pathname relative to the current working directory.
            let root_len = self.root_dir_len - 1;
            let cwd_len = self.cwd_len;
            let pathname_len = pathname.len();
            assert!(root_len + cwd_len + pathname_len < self.path_buf.len());
            let mut offset = 0;
            self.path_buf[offset..root_len].copy_from_slice(&self.root_dir_buf[0..root_len]);
            offset += root_len;
            self.path_buf[offset..offset + cwd_len].copy_from_slice(&self.cwd[0..cwd_len]);
            offset += cwd_len;
            self.path_buf[offset - 1] = b'/';
            self.path_buf[offset..offset + pathname_len].copy_from_slice(pathname);
            let a = &self.path_buf[0..offset + pathname_len];
            debug_println!(
                "\x1b[31m[kernel]\x1b[0m openat: path={:?}, root={:?}, cwd={:?}",
                unsafe { core::str::from_utf8_unchecked(a) },
                unsafe { core::str::from_utf8_unchecked(&self.root_dir_buf[0..root_len]) },
                unsafe { core::str::from_utf8_unchecked(&self.cwd[0..cwd_len]) },
            );
        } else {
            let root_len = self.root_dir_len - 1;
            let pathname_len = pathname.len();
            assert!(root_len + pathname_len < self.path_buf.len());
            self.path_buf[0..root_len].copy_from_slice(&self.root_dir_buf[0..root_len]);
            self.path_buf[root_len..root_len + pathname_len].copy_from_slice(pathname);
            debug_println!(
                "\x1b[31m[kernel]\x1b[0m openat: root_dir={:?} path={:?}",
                unsafe { core::str::from_utf8_unchecked(&self.root_dir_buf[0..root_len]) },
                unsafe {
                    core::str::from_utf8_unchecked(&self.path_buf[0..root_len + pathname_len])
                },
            );
        }

        let fd = unsafe { raw_syscall!(Sysno::openat, dirfd, self.path_buf.as_ptr(), flags, mode) };
        ucontext.set_syscall_ret(fd)
    }

    fn getcwd(&mut self, ucontext: &mut ucontext_t) {
        let (buf, size) = ucontext.syscall_arg2();
        unsafe {
            let max = self.cwd_len.min(size);
            let buf = buf as *mut u8;
            buf.copy_from_nonoverlapping(self.cwd.as_ptr(), max);
            debug_println!(
                "\x1b[31m[kernel]\x1b[0m getcwd: cwd={:?}",
                core::str::from_utf8_unchecked(core::slice::from_raw_parts(buf, max - 1))
            )
        }
        ucontext.set_syscall_ret(buf)
    }

    fn exit_group(&mut self, _ucontext: &mut ucontext_t) {
        let status = _ucontext.syscall_arg1();
        debug_println!("exit_group: {}", status);
        sys::exit_group(status as i32);
    }
}

impl FSSandbox {
    fn exit_with_help(exit_code: i32) -> ! {
        Self::help();
        sys::exit_group(exit_code)
    }
}

#[cfg(test)]
mod tests {
    use tvisor::{print, println};

    #[test_case]
    fn trivial_assertion() {
        print!("trivial assertion... ");
        assert_eq!(1, 1);
        println!("[ok]");
    }
}
