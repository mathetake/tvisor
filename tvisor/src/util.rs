use crate::sys;
use crate::sys::stat_t;

pub fn read_elf(path: &str) -> (*const u8, usize) {
    unsafe {
        let file_descriptor = match sys::open(path.as_ptr(), sys::O_RDONLY, 0) {
            Ok(fd) => fd as i32,
            Err(err) => {
                panic!("Failed to open file: {} at {}", err, path);
            }
        };

        let mut st = stat_t::default();
        sys::fstat(file_descriptor, &mut st).unwrap();
        let file_size = st.st_size as usize;
        assert!(file_size > 0, "File size is 0");
        let ptr = sys::mmap(
            0,
            file_size,
            sys::PROT_READ | sys::PROT_WRITE,
            sys::MAP_PRIVATE | sys::MAP_ANONYMOUS,
        );

        let view = core::slice::from_raw_parts_mut(ptr, file_size);
        let bytes_read = match sys::read(file_descriptor, view) {
            Ok(n) => n,
            Err(err) => {
                panic!("Failed to read file: {}", err);
            }
        };

        if bytes_read != file_size {
            panic!(
                "Failed to read file: read {} bytes, expected {}",
                bytes_read, file_size
            );
        }

        (ptr, file_size)
    }
}

pub fn cstr_from_ptr<'a>(ptr: *const u8) -> &'a str {
    unsafe {
        use core::slice;
        let mut len = 0;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        let slice = slice::from_raw_parts(ptr, len);
        core::str::from_utf8_unchecked(slice)
    }
}

/// Takes a test function name and body and generates a test function in which the body is started
/// with a call to println! to print the name of the test function.
#[cfg(test)]
#[macro_export]
macro_rules! test_case {
    ($name:ident, $body:block) => {
        #[test_case]
        fn $name() {
            crate::println_stdout!(
                "* Running {}@{}:{} ...",
                stringify!($name),
                file!(),
                line!()
            );
            $body
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::println_stdout;

    test_case!(test_cstr_from_ptr, {
        let s = "hello\0";
        let ptr = s.as_ptr();
        let result = cstr_from_ptr(ptr);
        assert_eq!(result, s.trim_end_matches('\0'));
    });

    test_case!(test_read_elf, {
        println_stdout!("Running test_read_elf...");
        let (ptr, file_size) = read_elf("/bin/sh\0");
        assert!(file_size > 0);
        sys::munmap(ptr, file_size);
    });
}
