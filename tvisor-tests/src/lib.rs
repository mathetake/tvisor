use std::io::Write;
use std::process::Command;

#[derive(Debug, Default, Clone)]
/// Represents a test case to be run.
pub struct TestCase {
    /// Path to the executable built on top of tvisor to be tested.
    pub executable_path: String,
    /// cwd to be passed to the process.
    pub cwd: String,
    /// Stdin to be passed to the process.
    pub stdin: String,
    /// Environment variables to be passed to the process.
    pub env_vars: String,
    /// Arguments to be passed to tvisor, ie the arguments before `--`.
    pub tvisor_args: String,
    /// Arguments to be passed to the executable, ie the arguments after `--`.
    pub args: String,
    /// Expected output of the executable that is used in the exact match with the stdout.
    pub expected_output: String,
    /// Expected output of the executable that is used in the contains match with the stdout.
    pub expected_output_contains: Vec<String>,
    /// Expected exit code of the executable.
    pub expected_exit_code: i32,
}

impl TestCase {
    pub fn with_executable_path(mut self, executable_path: &str) -> Self {
        self.executable_path = executable_path.to_string();
        self
    }

    pub fn with_cwd(mut self, cwd: &str) -> Self {
        self.cwd = cwd.to_string();
        self
    }

    pub fn with_stdin(mut self, stdin: &str) -> Self {
        self.stdin = stdin.to_string();
        self
    }

    pub fn with_env_vars(mut self, env_vars: &str) -> Self {
        self.env_vars = env_vars.to_string();
        self
    }

    pub fn with_tvisor_args(mut self, tvisor_args: &str) -> Self {
        self.tvisor_args = tvisor_args.to_string();
        self
    }

    pub fn with_args(mut self, args: &str) -> Self {
        self.args = args.to_string();
        self
    }

    pub fn with_expected_output(mut self, expected_output: &str) -> Self {
        self.expected_output = expected_output.to_string();
        self
    }

    pub fn with_expected_output_contains(mut self, expected_output_contains: &str) -> Self {
        self.expected_output_contains
            .push(expected_output_contains.to_string());
        self
    }

    pub fn with_expected_exit_code(mut self, expected_exit_code: i32) -> Self {
        self.expected_exit_code = expected_exit_code;
        self
    }

    /// Run the test case for both debug and release builds.
    pub fn run(&self) {
        self.run_debug();
        self.run_release();
    }

    /// Run the test case for release build.
    pub fn run_debug(&self) {
        self._run(self.executable_path.clone(), false);
    }

    /// Run the test case for release build.
    pub fn run_release(&self) {
        self._run(
            self.executable_path.clone().replace("debug", "release"),
            true,
        );
    }

    /// Run the test case.
    pub fn _run(&self, executable_path: String, is_release: bool) {
        let cmd = &mut Command::new(&executable_path);
        if !self.tvisor_args.is_empty() {
            cmd.args(self.tvisor_args.split_whitespace());
        }
        if !self.args.is_empty() {
            cmd.arg("--");
            cmd.args(self.args.split_whitespace());
        }
        if !self.env_vars.is_empty() {
            cmd.envs(Self::parse_env_vars(&self.env_vars));
        }

        if !self.cwd.is_empty() {
            cmd.current_dir(&self.cwd);
        }

        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        println!("===========================================================================");
        println!(
            "Running {} test case:",
            if is_release { "release" } else { "debug" }
        );
        println!("Executable Path: {}", executable_path);
        println!("CWD: {}", self.cwd);
        println!("Environment Variables: {}", self.env_vars);
        println!("tvisor Arguments: {}", self.tvisor_args);
        println!("Arguments: {}", self.args);
        println!("Expected Output: {}", self.expected_output);
        println!("Expected Exit Code: {}", self.expected_exit_code);
        println!("Stdin: {}", self.stdin);
        println!();
        println!("Full Command: {:?}", cmd);
        println!("===========================================================================");

        // Spawn the child process.
        let mut child = cmd.spawn().expect("Failed to execute test case");

        // Write stdin to the child process.
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(self.stdin.as_bytes()).unwrap();

        let output = child
            .wait_with_output()
            .expect("Failed to execute test case");

        let std_out = String::from_utf8_lossy(&output.stdout);
        let std_err = String::from_utf8_lossy(&output.stderr);

        // Check if std_err is empty, if not, print them.
        if !std_err.is_empty() {
            println!("> Stderr:");
            for line in std_err.lines() {
                println!(">>> {}", line);
            }
        }

        let code = output.status.code().expect("Failed to get exit code");
        if code != self.expected_exit_code {
            println!(
                "Test Failed:\nExpected exit code {}, but got {}\nStdout:\n{}",
                self.expected_exit_code, code, std_out
            );
            panic!("Test Failed");
        }

        if self.expected_output_contains.is_empty() && std_out.trim() != self.expected_output {
            println!(
                "Test Failed:\nExpected '{}', but got '{}'",
                self.expected_output,
                std_out.trim(),
            );
            panic!("Test Failed");
        }

        for expected_output_contain in &self.expected_output_contains {
            if !std_out.contains(expected_output_contain) {
                println!(
                    "Test Failed:\nExpected '{}' contained, but got '{}'",
                    expected_output_contain,
                    std_out.trim()
                );
                panic!("Test Failed");
            }
        }
        println!(
            "\n\n================================Test Passed=================================\n\n"
        );
    }

    fn parse_env_vars(env_vars: &str) -> std::collections::HashMap<String, String> {
        env_vars
            .split_whitespace()
            .map(|var| {
                let mut parts = var.split('=');
                (
                    parts.next().unwrap_or_default().to_string(),
                    parts.next().unwrap_or_default().to_string(),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod fs {
    use super::*;
    use std::io::BufRead;
    use tempfile::tempdir;

    fn test_case_executable_path(test_case: &str) -> String {
        format!(
            "{}/{}",
            std::env::var("TVISOR_TEST_C_CASES_DIR").unwrap(),
            test_case,
        )
    }

    fn executable_path() -> String {
        std::env::var("TVISOR_FS_EXECUTABLE").unwrap()
    }

    const EXP_HELP: &str = r#"tvisor: a Tiny Thread-level syscall monitor on Linux

Usage: tvisor [options] -- <program> [args]
Options:
  -c, --cwd <dir>: set the current working directory to <dir>, defaults to /
  -r, --root <dir>: mount the host directory <dir> as the root for the guest, defaults to /
  -h, --help: print this help message"#;

    #[test]
    fn unknown_option() {
        TestCase::default()
            .with_executable_path(executable_path().as_str())
            .with_tvisor_args("--unknown-option")
            .with_expected_exit_code(1)
            .with_expected_output(format!("Unknown option: --unknown-option\n{EXP_HELP}").as_str())
            .run();
    }

    #[test]
    fn explicit_help() {
        TestCase::default()
            .with_executable_path(executable_path().as_str())
            .with_tvisor_args("--help")
            .with_expected_output(EXP_HELP)
            .run();
    }

    #[test]
    fn default_help() {
        TestCase::default()
            .with_executable_path(executable_path().as_str())
            .with_expected_output(EXP_HELP)
            .run();
    }

    #[test]
    fn write_file_absolute_path() {
        let binding = tempdir().unwrap();
        let tmp_dir = binding.path();
        // Absolute path.
        TestCase::default()
            .with_executable_path(executable_path().as_str())
            .with_tvisor_args(format!("--root {}", tmp_dir.to_str().unwrap()).as_str())
            .with_args(format!("{} /tmp.txt", test_case_executable_path("write_file")).as_str())
            .with_expected_exit_code(0)
            .with_expected_output("")
            .run();

        // Check if the file is created.
        let file_path = format!("{}/tmp.txt", tmp_dir.to_str().unwrap());
        let file = std::fs::File::open(file_path).unwrap();
        let mut reader = std::io::BufReader::new(file);
        let mut buf = String::new();
        reader.read_line(&mut buf).unwrap();
        assert_eq!(buf, "Hello, file named /tmp.txt!\n");
    }

    #[test]
    fn write_file_relative_path() {
        let binding = tempdir().unwrap();
        let tmp_dir = binding.path();
        TestCase::default()
            .with_executable_path(executable_path().as_str())
            .with_tvisor_args(format!("--root {}", tmp_dir.to_str().unwrap()).as_str())
            .with_args(format!("{} tmp.txt", test_case_executable_path("write_file")).as_str())
            .with_expected_exit_code(0)
            .with_expected_output("")
            .run();
        // Check if the file is created.
        let file_path = format!("{}/tmp.txt", tmp_dir.to_str().unwrap());
        let file = std::fs::File::open(file_path).unwrap();
        let mut reader = std::io::BufReader::new(file);
        let mut buf = String::new();
        reader.read_line(&mut buf).unwrap();
        assert_eq!(buf, "Hello, file named tmp.txt!\n");
    }

    #[test]
    fn write_file_relative_path_subdir() {
        let binding = tempdir().unwrap();
        let tmp_dir = binding.path();
        std::fs::create_dir(format!("{}/subdir", tmp_dir.to_str().unwrap())).unwrap();

        // Relative path on the cwd.
        TestCase::default()
            .with_executable_path(executable_path().as_str())
            .with_tvisor_args(
                format!("--root {} --cwd /subdir", tmp_dir.to_str().unwrap()).as_str(),
            )
            .with_args(format!("{} tmp.txt", test_case_executable_path("write_file")).as_str())
            .with_expected_exit_code(0)
            .with_expected_output("")
            .run();

        // Check if the file is created.
        let file_path = format!("{}/subdir/tmp.txt", tmp_dir.to_str().unwrap());
        let file = std::fs::File::open(file_path).unwrap();
        let mut reader = std::io::BufReader::new(file);
        let mut buf = String::new();
        reader.read_line(&mut buf).unwrap();
        assert_eq!(buf, "Hello, file named tmp.txt!\n");

        // Relative path on the subdir.
        TestCase::default()
            .with_executable_path(executable_path().as_str())
            .with_tvisor_args(format!("--root {}", tmp_dir.to_str().unwrap()).as_str())
            .with_args(
                format!(
                    "{} subdir/tmp2.txt",
                    test_case_executable_path("write_file")
                )
                .as_str(),
            )
            .with_expected_exit_code(0)
            .with_expected_output("")
            .run();
        // Check if the file is created.
        let file_path = format!("{}/subdir/tmp2.txt", tmp_dir.to_str().unwrap());
        let file = std::fs::File::open(file_path).unwrap();
        let mut reader = std::io::BufReader::new(file);
        let mut buf = String::new();
        reader.read_line(&mut buf).unwrap();
        assert_eq!(buf, "Hello, file named subdir/tmp2.txt!\n");
    }

    #[test]
    fn hello_world() {
        TestCase::default()
            .with_executable_path(executable_path().as_str())
            .with_args(test_case_executable_path("hello_world").as_str())
            .with_expected_exit_code(0)
            .with_expected_output("Hello, World!")
            .run();
    }

    #[test]
    fn print_arg() {
        TestCase::default()
            .with_executable_path(executable_path().as_str())
            .with_args(format!("{} my arg yeah", test_case_executable_path("print_arg")).as_str())
            .with_expected_exit_code(0)
            .with_expected_output(
                format!("{}\nmy\narg\nyeah", test_case_executable_path("print_arg")).as_str(),
            )
            .run();
    }

    #[test]
    fn getcwd() {
        let test_case = TestCase::default()
            .with_executable_path(executable_path().as_str())
            .with_args(test_case_executable_path("getcwd").as_str())
            .with_expected_exit_code(0)
            .with_expected_output("Current working directory: /");
        test_case.run();
        test_case
            .with_tvisor_args("--cwd /tmp")
            .with_expected_output("Current working directory: /tmp")
            .run();
    }

    #[test]
    fn getcwd_with_root_dir() {
        let test_case = TestCase::default()
            .with_executable_path(executable_path().as_str())
            .with_tvisor_args("--root /tmp")
            .with_args(test_case_executable_path("getcwd").as_str())
            .with_expected_exit_code(0)
            .with_expected_output("Current working directory: /");
        test_case.run();
        test_case
            .with_tvisor_args("--root /tmp --cwd /tmp/foo/bar")
            .with_expected_output("Current working directory: /tmp/foo/bar")
            .run();
    }

    #[test]
    fn env() {
        TestCase::default()
            .with_executable_path(executable_path().as_str())
            .with_env_vars("FOO_YEAH=1 FOO_WHAT=100")
            .with_args(test_case_executable_path("env").as_str())
            .with_expected_exit_code(0)
            .with_expected_output("FOO_YEAH: 1\nFOO_WHAT: 100")
            .run();
    }
}

#[cfg(test)]
mod nop {
    use super::*;

    fn test_case_executable_path(test_case: &str) -> String {
        format!(
            "{}/{}",
            std::env::var("TVISOR_TEST_C_CASES_DIR").unwrap(),
            test_case,
        )
    }

    fn executable_path() -> String {
        std::env::var("TVISOR_NOP_EXECUTABLE").unwrap()
    }

    #[test]
    fn default() {
        TestCase::default()
            .with_executable_path(executable_path().as_str())
            .with_expected_exit_code(0)
            .with_expected_output("tvisor-nop: does nothing")
            .run();
    }

    #[test]
    fn basic_signal() {
        TestCase::default()
            .with_executable_path(executable_path().as_str())
            .with_args(test_case_executable_path("basic_signal").as_str())
            .with_expected_exit_code(0)
            .with_expected_output("Received signal 10")
            .run();
    }

    #[test]
    fn sigprocmask() {
        TestCase::default()
            .with_executable_path(executable_path().as_str())
            .with_args(test_case_executable_path("sigprocmask").as_str())
            .with_expected_exit_code(0)
            .run();
    }

    #[test]
    fn multithread_simple() {
        TestCase::default()
            .with_executable_path(executable_path().as_str())
            .with_args(test_case_executable_path("multithread_simple").as_str())
            .with_expected_exit_code(0)
            .with_expected_output("Final global counter value: 5000000")
            .run();
    }

    #[test]
    fn calling_conv() {
        TestCase::default()
            .with_executable_path(executable_path().as_str())
            .with_args(test_case_executable_path("calling_conv").as_str())
            .with_expected_exit_code(0)
            .with_expected_output("")
            .run();
    }

    #[test]
    fn calling_conv_clone() {
        TestCase::default()
            .with_executable_path(executable_path().as_str())
            .with_args(test_case_executable_path("calling_conv_clone").as_str())
            .with_expected_exit_code(0)
            .with_expected_output(
                r#"Child Thread Done
Parent Thread Done"#,
            )
            .run();
    }

    #[test]
    fn thread_local() {
        TestCase::default()
            .with_executable_path(executable_path().as_str())
            .with_args(test_case_executable_path("thread_local").as_str())
            .with_expected_exit_code(0)
            .with_expected_output_contains("Thread 2: Initial thread_counter = 2")
            .with_expected_output_contains("Thread 2: thread_counter = 3")
            .with_expected_output_contains("Thread 2: thread_counter = 4")
            .with_expected_output_contains("Thread 2: thread_counter = 5")
            .with_expected_output_contains("Thread 2: thread_counter = 6")
            .with_expected_output_contains("Thread 2: thread_counter = 502")
            .with_expected_output_contains("Thread 1: Initial thread_counter = 1")
            .with_expected_output_contains("Thread 1: thread_counter = 2")
            .with_expected_output_contains("Thread 1: thread_counter = 3")
            .with_expected_output_contains("Thread 1: thread_counter = 4")
            .with_expected_output_contains("Thread 1: thread_counter = 5")
            .with_expected_output_contains("Thread 1: thread_counter = 501")
            .with_expected_output_contains("Thread 0: Initial thread_counter = 0")
            .with_expected_output_contains("Thread 0: thread_counter = 1")
            .with_expected_output_contains("Thread 0: thread_counter = 2")
            .with_expected_output_contains("Thread 0: thread_counter = 3")
            .with_expected_output_contains("Thread 0: thread_counter = 4")
            .with_expected_output_contains("Thread 0: thread_counter = 500")
            .run();
    }

    #[test]
    fn thread_local_complex() {
        TestCase::default()
            .with_executable_path(executable_path().as_str())
            .with_args(test_case_executable_path("thread_local_complex").as_str())
            .with_expected_output_contains(
                "Main thread current value: ToolA = 5, ToolB = 10, ToolC = 15",
            )
            .with_expected_output_contains(
                "Worker 4 current value: ToolA = 5, ToolB = 10, ToolC = 15",
            )
            .with_expected_output_contains("Worker 4: Result of operation = 371")
            .with_expected_output_contains(
                "Worker 3 current value: ToolA = 5, ToolB = 10, ToolC = 15",
            )
            .with_expected_output_contains("Worker 3: Result of operation = 252")
            .with_expected_output_contains(
                "Worker 2 current value: ToolA = 5, ToolB = 10, ToolC = 15",
            )
            .with_expected_output_contains("Worker 2: Result of operation = 153")
            .with_expected_output_contains(
                "Worker 1 current value: ToolA = 5, ToolB = 10, ToolC = 15",
            )
            .with_expected_output_contains("Worker 1: Result of operation = 74")
            .with_expected_exit_code(0)
            .run();
    }

    #[test]
    fn nested_fork() {
        TestCase::default()
            .with_executable_path(executable_path().as_str())
            .with_args(test_case_executable_path("nested_fork").as_str())
            .with_expected_output_contains("Grandchild UID: 9999")
            .with_expected_output_contains("First child UID: 9999")
            .with_expected_exit_code(0)
            .run();
    }

    #[test]
    fn execv() {
        TestCase::default()
            .with_executable_path(executable_path().as_str())
            .with_args(test_case_executable_path("execv").as_str())
            .with_expected_output(
                r#"MY_CUSTOM_ENV is: HelloWorld
UID in new exec: 9999"#,
            )
            .with_expected_exit_code(0)
            .run();
    }

    #[test]
    fn sighandler() {
        TestCase::default()
            .with_executable_path(executable_path().as_str())
            .with_args(test_case_executable_path("sighandler").as_str())
            .with_expected_output(
                r#"Raising SIGTERM signal.
UID at SIGTERM: 9999
Received SIGTERM
Raising SIGINT signal.
UID at SIGINT: 19998
Received SIGINT
UID at the end: 29997"#,
            )
            .with_expected_exit_code(0)
            .run();
    }

    #[test]
    fn sighandler_multithreads() {
        TestCase::default()
            .with_executable_path(executable_path().as_str())
            .with_args(test_case_executable_path("sighandler_multithreads").as_str())
            .with_expected_output_contains("Received SIGINT")
            .with_expected_output_contains("Received SIGTERM")
            .with_expected_exit_code(0)
            .run();
    }

    #[test]
    fn pthread_cancel() {
        TestCase::default()
            .with_executable_path(executable_path().as_str())
            .with_args(test_case_executable_path("pthread_cancel").as_str())
            .with_expected_output_contains("main: sem_wait")
            .with_expected_output_contains("main: pthread_join done")
            .with_expected_output_contains("child: start")
            .with_expected_output_contains("child: sem_post")
            .with_expected_exit_code(0)
            .run();
    }

    #[test]
    fn initial_signal() {
        let mut exp_output = String::new();
        for i in 1..=64 {
            exp_output.push_str(&format!("Signal {} is not blocked.\n", i));
        }
        TestCase::default()
            .with_executable_path(executable_path().as_str())
            .with_args(test_case_executable_path("initial_signal").as_str())
            .with_expected_output_contains(exp_output.as_str().trim_end())
            .with_expected_exit_code(0)
            .run();
    }

    #[test]
    fn sighandler_default_aborts() {
        fn run(i: i32, exp: &str) {
            let args = format!("{} {}", test_case_executable_path("sighandler_default"), i);
            TestCase::default()
                .with_executable_path(executable_path().as_str())
                .with_args(args.as_str())
                .with_expected_output_contains(exp)
                .with_expected_exit_code(128 + i)
                .run();
        }
        run(1, "aborting with");
        run(2, "aborting with");
        run(3, "aborting with");
        run(4, "Illegal instruction");
        run(5, "aborting with");
        run(6, "aborting with");
        run(7, "Bus error");
        run(0xb, "Segmentation fault");
    }

    #[test]
    fn sighandler_default_ignores() {
        fn run(i: i32) {
            let args = format!("{} {}", test_case_executable_path("sighandler_default"), i);
            TestCase::default()
                .with_executable_path(executable_path().as_str())
                .with_args(args.as_str())
                .with_expected_exit_code(0)
                .with_expected_output_contains("successfully sent to thread")
                .run();
        }
        run(17);
        run(18);
    }

    #[test]
    fn blocked_synchronous_sigs() {
        TestCase::default()
            .with_executable_path(executable_path().as_str())
            .with_args(test_case_executable_path("blocked_sigill").as_str())
            .with_expected_output_contains("Illegal instruction")
            .with_expected_exit_code(128 + 0x4)
            .run();
        TestCase::default()
            .with_executable_path(executable_path().as_str())
            .with_args(test_case_executable_path("blocked_segfault").as_str())
            .with_expected_output_contains("Segmentation fault")
            .with_expected_exit_code(128 + 0xb)
            .run();
    }

    #[test]
    fn vfork() {
        let test_case = TestCase::default()
            .with_executable_path(executable_path().as_str())
            .with_args(test_case_executable_path("vfork").as_str())
            .with_expected_exit_code(0)
            .with_expected_output_contains("Child process has terminated")
            .with_expected_output_contains("Forking once:");
        test_case.run();
    }

    #[test]
    fn sighandler_fork() {
        let test_case = TestCase::default()
            .with_executable_path(executable_path().as_str())
            .with_args(test_case_executable_path("sighandler_fork").as_str())
            .with_expected_exit_code(0)
            .with_expected_output_contains("exited with status: 0");
        test_case.run();
    }

    #[test]
    fn sighandler_continuation_sleep() {
        let test_case = TestCase::default()
            .with_executable_path(executable_path().as_str())
            .with_args(test_case_executable_path("sighandler_continuation_sleep").as_str())
            .with_expected_exit_code(0)
            .with_env_vars("CLOC_NANO_SLEEP=1")
            .with_expected_output(
                r#"Use clock_nanosleep
Continuation is after 1 second"#,
            );
        test_case.run();
        test_case
            .with_env_vars("")
            .with_expected_output(
                r#"Use sleep
Continuation is after 1 second"#,
            )
            .run();
    }

    mod musl_libc {
        use crate::nop::executable_path;
        use tempfile::tempdir;

        fn test_case_executable_path(test_case: &str) -> String {
            format!(
                "{}/{}",
                std::env::var("TVISOR_TEST_MUSL_LIBC_CASES_DIR").unwrap(),
                test_case,
            )
        }

        macro_rules! test_case {
            ($test_name:ident,$test_file_name:literal) => {
                #[test]
                fn $test_name() {
                    let binding = tempdir().unwrap();
                    let tmp_dir = binding.path();

                    let test_case = super::TestCase::default()
                        .with_executable_path(executable_path().as_str())
                        .with_args(test_case_executable_path($test_file_name).as_str())
                        .with_expected_exit_code(0)
                        .with_cwd(tmp_dir.to_str().unwrap());
                    test_case.run();
                }
            };
            ($test_name:ident, $test_file_name:literal, $ignore:expr) => {
                #[test]
                #[ignore]
                fn $test_name() {}
            };
        }

        test_case!(basename_static, "basename-static.exe");
        test_case!(strtod_simple_static, "strtod_simple-static.exe");
        test_case!(memmem_oob_read, "memmem-oob-read.exe");
        test_case!(tgmath_static, "tgmath-static.exe");
        test_case!(regex_bracket_icase, "regex-bracket-icase.exe");
        test_case!(pthread_tsd_static, "pthread_tsd-static.exe");
        test_case!(wcstol_static, "wcstol-static.exe");
        test_case!(sem_close_unmap, "sem_close-unmap.exe");
        test_case!(pleval_static, "pleval-static.exe");
        test_case!(iconv_open, "iconv_open.exe");
        test_case!(
            scanf_match_literal_eof_static,
            "scanf-match-literal-eof-static.exe"
        );
        test_case!(search_tsearch, "search_tsearch.exe");
        test_case!(dirname, "dirname.exe");
        test_case!(swprintf_static, "swprintf-static.exe");
        test_case!(mbc_static, "mbc-static.exe");
        test_case!(scanf_bytes_consumed, "scanf-bytes-consumed.exe");
        test_case!(strtof, "strtof.exe");
        test_case!(getpwnam_r_crash, "getpwnam_r-crash.exe");
        test_case!(setenv_oom, "setenv-oom.exe");
        test_case!(strtod, "strtod.exe");
        test_case!(search_lsearch, "search_lsearch.exe");
        test_case!(strftime, "strftime.exe");
        test_case!(string_strchr_static, "string_strchr-static.exe");
        test_case!(inet_ntop_v4mapped, "inet_ntop-v4mapped.exe");
        test_case!(sscanf_eof_static, "sscanf-eof-static.exe");
        test_case!(iconv_roundtrips_static, "iconv-roundtrips-static.exe");
        test_case!(syscall_sign_extend, "syscall-sign-extend.exe");
        test_case!(random_static, "random-static.exe");
        test_case!(udiv, "udiv.exe");
        test_case!(regex_bracket_icase_static, "regex-bracket-icase-static.exe");
        test_case!(qsort, "qsort.exe");
        test_case!(string, "string.exe");
        test_case!(
            wcsncpy_read_overflow_static,
            "wcsncpy-read-overflow-static.exe"
        );
        test_case!(statvfs, "statvfs.exe");
        test_case!(sscanf_long_static, "sscanf_long-static.exe");
        test_case!(strverscmp, "strverscmp.exe");
        test_case!(inet_ntop_v4mapped_static, "inet_ntop-v4mapped-static.exe");
        test_case!(setenv_oom_static, "setenv-oom-static.exe");
        test_case!(
            pthread_cond_smasher_static,
            "pthread_cond-smasher-static.exe"
        );
        test_case!(memstream_static, "memstream-static.exe");
        test_case!(clocale_mbfuncs_static, "clocale_mbfuncs-static.exe");
        test_case!(ungetc_static, "ungetc-static.exe");
        test_case!(pthread_create_oom, "pthread_create-oom.exe");
        test_case!(pthread_exit_dtor_static, "pthread_exit-dtor-static.exe");
        test_case!(mbc, "mbc.exe");
        test_case!(fflush_exit, "fflush-exit.exe");
        test_case!(putenv_doublefree, "putenv-doublefree.exe");
        test_case!(fdopen_static, "fdopen-static.exe");
        test_case!(pthread_mutex_pi_static, "pthread_mutex_pi-static.exe");
        test_case!(rewind_clear_error, "rewind-clear-error.exe");
        test_case!(
            ftello_unflushed_append_static,
            "ftello-unflushed-append-static.exe"
        );
        test_case!(setjmp, "setjmp.exe");
        test_case!(regex_escaped_high_byte, "regex-escaped-high-byte.exe");
        test_case!(socket, "socket.exe");
        test_case!(sigprocmask_internal, "sigprocmask-internal.exe");
        test_case!(mbsrtowcs_overflow_static, "mbsrtowcs-overflow-static.exe");
        test_case!(time_static, "time-static.exe");
        test_case!(udiv_static, "udiv-static.exe");
        test_case!(setjmp_static, "setjmp-static.exe");
        test_case!(random, "random.exe");
        test_case!(clock_gettime, "clock_gettime.exe");
        test_case!(scanf_nullbyte_char, "scanf-nullbyte-char.exe");
        test_case!(string_static, "string-static.exe");
        test_case!(mkdtemp_failure_static, "mkdtemp-failure-static.exe");
        test_case!(fnmatch_static, "fnmatch-static.exe");
        test_case!(mbsrtowcs_overflow, "mbsrtowcs-overflow.exe");
        test_case!(wcsncpy_read_overflow, "wcsncpy-read-overflow.exe");
        test_case!(getpwnam_r_crash_static, "getpwnam_r-crash-static.exe");
        test_case!(pthread_cond_smasher, "pthread_cond-smasher.exe");
        test_case!(scanf_nullbyte_char_static, "scanf-nullbyte-char-static.exe");
        test_case!(pthread_rwlock_ebusy, "pthread_rwlock-ebusy.exe");
        test_case!(printf_1e9_oob, "printf-1e9-oob.exe");
        test_case!(string_strcspn_static, "string_strcspn-static.exe");
        test_case!(fcntl_static, "fcntl-static.exe");
        test_case!(dn_expand_ptr_0_static, "dn_expand-ptr-0-static.exe");
        test_case!(strtod_long, "strtod_long.exe");
        test_case!(string_strcspn, "string_strcspn.exe");
        test_case!(setvbuf_unget, "setvbuf-unget.exe");
        test_case!(string_strstr, "string_strstr.exe");
        test_case!(string_memcpy_static, "string_memcpy-static.exe");
        test_case!(
            pthread_once_deadlock_static,
            "pthread_once-deadlock-static.exe"
        );
        test_case!(search_insque_static, "search_insque-static.exe");
        test_case!(dirname_static, "dirname-static.exe");
        test_case!(tls_init, "tls_init.exe");
        test_case!(sigreturn_static, "sigreturn-static.exe");
        test_case!(ipc_shm_static, "ipc_shm-static.exe");
        test_case!(string_memmem, "string_memmem.exe");
        test_case!(strtod_long_static, "strtod_long-static.exe");
        test_case!(stat, "stat.exe");
        test_case!(dn_expand_empty, "dn_expand-empty.exe");
        test_case!(fgetwc_buffering_static, "fgetwc-buffering-static.exe");
        test_case!(malloc_0_static, "malloc-0-static.exe");
        test_case!(string_strchr, "string_strchr.exe");
        test_case!(argv, "argv.exe");
        test_case!(fflush_exit_static, "fflush-exit-static.exe");
        test_case!(pthread_tsd, "pthread_tsd.exe");
        test_case!(iswspace_null, "iswspace-null.exe");
        test_case!(pthread_cancel_sem_wait, "pthread_cancel-sem_wait.exe");
        test_case!(
            pthread_cancel_sem_wait_static,
            "pthread_cancel-sem_wait-static.exe"
        );
        test_case!(pthread_cond, "pthread_cond.exe");
        test_case!(inet_pton_empty_last_field, "inet_pton-empty-last-field.exe");
        test_case!(
            sigprocmask_internal_static,
            "sigprocmask-internal-static.exe"
        );
        test_case!(env_static, "env-static.exe");
        test_case!(strtod_simple, "strtod_simple.exe");
        test_case!(mkdtemp_failure, "mkdtemp-failure.exe");
        test_case!(fscanf_static, "fscanf-static.exe");
        test_case!(ungetc, "ungetc.exe");
        test_case!(sscanf_static, "sscanf-static.exe");
        test_case!(uselocale_0_static, "uselocale-0-static.exe");
        test_case!(sem_open, "sem_open.exe");
        test_case!(tls_local_exec_static, "tls_local_exec-static.exe");
        test_case!(lrand48_signextend_static, "lrand48-signextend-static.exe");
        test_case!(search_tsearch_static, "search_tsearch-static.exe");
        test_case!(
            inet_pton_empty_last_field_static,
            "inet_pton-empty-last-field-static.exe"
        );
        test_case!(crypt, "crypt.exe");
        test_case!(
            pthread_cond_wait_cancel_ignored,
            "pthread_cond_wait-cancel_ignored.exe"
        );
        test_case!(search_lsearch_static, "search_lsearch-static.exe");
        test_case!(printf_fmt_g_zeros_static, "printf-fmt-g-zeros-static.exe");
        test_case!(flockfile_list, "flockfile-list.exe");
        test_case!(pthread_exit_dtor, "pthread_exit-dtor.exe");
        test_case!(snprintf, "snprintf.exe");
        test_case!(stat_static, "stat-static.exe");
        test_case!(pthread_mutex, "pthread_mutex.exe");
        test_case!(strtold_static, "strtold-static.exe");
        test_case!(time, "time.exe");
        test_case!(printf_fmt_n, "printf-fmt-n.exe");
        test_case!(printf_fmt_g_zeros, "printf-fmt-g-zeros.exe");
        test_case!(lrand48_signextend, "lrand48-signextend.exe");
        test_case!(memmem_oob_read_static, "memmem-oob-read-static.exe");
        test_case!(ipc_msg_static, "ipc_msg-static.exe");
        test_case!(regex_ere_backref_static, "regex-ere-backref-static.exe");
        test_case!(argv_static, "argv-static.exe");
        test_case!(regex_ere_backref, "regex-ere-backref.exe");
        test_case!(pthread_mutex_pi, "pthread_mutex_pi.exe");
        test_case!(wcsstr_static, "wcsstr-static.exe");
        test_case!(regexec_nosub, "regexec-nosub.exe");
        test_case!(sscanf_long, "sscanf_long.exe");
        test_case!(fdopen, "fdopen.exe");
        test_case!(lseek_large_static, "lseek-large-static.exe");
        test_case!(wcsstr, "wcsstr.exe");
        test_case!(iconv_roundtrips, "iconv-roundtrips.exe");
        test_case!(fpclassify_invalid_ld80, "fpclassify-invalid-ld80.exe");
        test_case!(printf_1e9_oob_static, "printf-1e9-oob-static.exe");
        test_case!(rlimit_open_files_static, "rlimit-open-files-static.exe");
        test_case!(
            scanf_bytes_consumed_static,
            "scanf-bytes-consumed-static.exe"
        );
        test_case!(sem_open_static, "sem_open-static.exe");
        test_case!(socket_static, "socket-static.exe");
        test_case!(clocale_mbfuncs, "clocale_mbfuncs.exe");
        test_case!(tls_init_static, "tls_init-static.exe");
        test_case!(daemon_failure_static, "daemon-failure-static.exe");
        test_case!(fscanf, "fscanf.exe");
        test_case!(getpwnam_r_errno_static, "getpwnam_r-errno-static.exe");
        test_case!(inet_pton, "inet_pton.exe");
        test_case!(ipc_msg, "ipc_msg.exe");
        test_case!(pthread_robust_detach, "pthread-robust-detach.exe");
        test_case!(sem_init, "sem_init.exe");
        test_case!(strverscmp_static, "strverscmp-static.exe");
        test_case!(fgetwc_buffering, "fgetwc-buffering.exe");
        test_case!(pthread_create_oom_static, "pthread_create-oom-static.exe");
        test_case!(regexec_nosub_static, "regexec-nosub-static.exe");
        test_case!(inet_pton_static, "inet_pton-static.exe");
        test_case!(string_memcpy, "string_memcpy.exe");
        test_case!(rlimit_open_files, "rlimit-open-files.exe");
        test_case!(fwscanf_static, "fwscanf-static.exe");
        test_case!(regex_backref_0, "regex-backref-0.exe");
        test_case!(utime_static, "utime-static.exe");
        test_case!(string_memset_static, "string_memset-static.exe");
        test_case!(iconv_open_static, "iconv_open-static.exe");
        test_case!(
            wcsstr_false_negative_static,
            "wcsstr-false-negative-static.exe"
        );
        test_case!(strtof_static, "strtof-static.exe");
        test_case!(setvbuf_unget_static, "setvbuf-unget-static.exe");
        test_case!(
            pthread_cond_wait_cancel_ignored_static,
            "pthread_cond_wait-cancel_ignored-static.exe"
        );
        test_case!(mkstemp_failure, "mkstemp-failure.exe");
        test_case!(sscanf, "sscanf.exe");
        test_case!(search_hsearch, "search_hsearch.exe");
        test_case!(flockfile_list_static, "flockfile-list-static.exe");
        test_case!(ftello_unflushed_append, "ftello-unflushed-append.exe");
        test_case!(lseek_large, "lseek-large.exe");
        test_case!(search_hsearch_static, "search_hsearch-static.exe");
        test_case!(iswspace_null_static, "iswspace-null-static.exe");
        test_case!(malloc_oom_static, "malloc-oom-static.exe");
        test_case!(scanf_match_literal_eof, "scanf-match-literal-eof.exe");
        test_case!(snprintf_static, "snprintf-static.exe");
        test_case!(printf_fmt_g_round, "printf-fmt-g-round.exe");
        test_case!(statvfs_static, "statvfs-static.exe");
        test_case!(qsort_static, "qsort-static.exe");
        test_case!(malloc_oom, "malloc-oom.exe");
        test_case!(printf_fmt_n_static, "printf-fmt-n-static.exe");
        test_case!(sem_init_static, "sem_init-static.exe");
        test_case!(daemon_failure, "daemon-failure.exe");
        test_case!(strtol_static, "strtol-static.exe");
        test_case!(printf_fmt_g_round_static, "printf-fmt-g-round-static.exe");
        test_case!(ipc_sem_static, "ipc_sem-static.exe");
        test_case!(sigreturn, "sigreturn.exe");
        test_case!(pthread_once_deadlock, "pthread_once-deadlock.exe");
        test_case!(
            regex_escaped_high_byte_static,
            "regex-escaped-high-byte-static.exe"
        );
        test_case!(mkstemp_failure_static, "mkstemp-failure-static.exe");
        test_case!(pthread_condattr_setclock, "pthread_condattr_setclock.exe");
        test_case!(pthread_mutex_static, "pthread_mutex-static.exe");
        test_case!(fnmatch, "fnmatch.exe");
        test_case!(pthread_exit_cancel, "pthread_exit-cancel.exe");
        test_case!(pthread_exit_cancel_static, "pthread_exit-cancel-static.exe");
        test_case!(memmem_oob, "memmem-oob.exe");
        test_case!(malloc_0, "malloc-0.exe");
        test_case!(dn_expand_ptr_0, "dn_expand-ptr-0.exe");
        test_case!(tgmath, "tgmath.exe");
        test_case!(regex_backref_0_static, "regex-backref-0-static.exe");
        test_case!(pthread_cond_static, "pthread_cond-static.exe");
        test_case!(getpwnam_r_errno, "getpwnam_r-errno.exe");
        test_case!(string_memset, "string_memset.exe");
        test_case!(swprintf, "swprintf.exe");

        test_case!(sscanf_eof, "sscanf-eof.exe");
        test_case!(clock_gettime_static, "clock_gettime-static.exe");
        test_case!(ipc_sem, "ipc_sem.exe");
        test_case!(strtol, "strtol.exe");
        test_case!(
            pthread_robust_detach_static,
            "pthread-robust-detach-static.exe"
        );
        test_case!(syscall_sign_extend_static, "syscall-sign-extend-static.exe");
        test_case!(regex_negated_range_static, "regex-negated-range-static.exe");
        test_case!(memstream, "memstream.exe");
        test_case!(regex_negated_range, "regex-negated-range.exe");
        test_case!(
            pthread_condattr_setclock_static,
            "pthread_condattr_setclock-static.exe"
        );
        test_case!(rewind_clear_error_static, "rewind-clear-error-static.exe");
        test_case!(env, "env.exe");
        test_case!(memmem_oob_static, "memmem-oob-static.exe");
        test_case!(strtod_static, "strtod-static.exe");
        test_case!(string_memmem_static, "string_memmem-static.exe");
        test_case!(pthread_cancel_points, "pthread_cancel-points.exe");
        test_case!(
            pthread_cancel_points_static,
            "pthread_cancel-points-static.exe"
        );
        test_case!(basename, "basename.exe");
        test_case!(string_strstr_static, "string_strstr-static.exe");
        test_case!(wcsstr_false_negative, "wcsstr-false-negative.exe");
        test_case!(strtold, "strtold.exe");
        test_case!(
            fpclassify_invalid_ld80_static,
            "fpclassify-invalid-ld80-static.exe"
        );
        test_case!(dn_expand_empty_static, "dn_expand-empty-static.exe");
        test_case!(crypt_static, "crypt-static.exe");
        test_case!(strftime_static, "strftime-static.exe");
        test_case!(fgets_eof, "fgets-eof.exe");
        test_case!(ipc_shm, "ipc_shm.exe");
        test_case!(fgets_eof_static, "fgets-eof-static.exe");
        test_case!(uselocale_0, "uselocale-0.exe");
        test_case!(fwscanf, "fwscanf.exe");
        test_case!(wcstol, "wcstol.exe");
        test_case!(tls_align_static, "tls_align-static.exe");
        test_case!(putenv_doublefree_static, "putenv-doublefree-static.exe");
        test_case!(sem_close_unmap_static, "sem_close-unmap-static.exe");
        test_case!(fcntl, "fcntl.exe");
        test_case!(tls_local_exec, "tls_local_exec.exe");
        test_case!(
            pthread_rwlock_ebusy_static,
            "pthread_rwlock-ebusy-static.exe"
        );
        test_case!(search_insque, "search_insque.exe");
        test_case!(pthread_robust, "pthread_robust.exe");
        test_case!(pthread_robust_static, "pthread_robust-static.exe");
        test_case!(
            pthread_atfork_errno_clobber,
            "pthread_atfork-errno-clobber.exe"
        );
        test_case!(
            pthread_atfork_errno_clobber_static,
            "pthread_atfork-errno-clobber-static.exe"
        );
        test_case!(pthread_cancel, "pthread_cancel.exe");
        test_case!(pthread_cancel_static, "pthread_cancel-static.exe");

        // Ignored cases:
        #[allow(dead_code)]
        const SKIP_UNTIL_SHARED_LIBRARY_IS_SUPPORTED: &str =
            "skip until shared library is supported";
        #[allow(dead_code)]
        const SKIP_UNTIL_BETTER_IDEA_NOT_TO_USE_TVOSR_DEFINED_SIGALTSTACK: &str =
            "until better idea not to use tvisor defined sigaltstack";

        test_case!(vfork, "vfork.exe", SKIP_UNTIL_SHARED_LIBRARY_IS_SUPPORTED);
        test_case!(
            vfork_static,
            "vfork-static.exe",
            SKIP_UNTIL_SHARED_LIBRARY_IS_SUPPORTED
        );
        test_case!(raise_race, "raise-race.exe", "hangs");
        test_case!(raise_race_static, "raise-race-static.exe", "hangs");
        test_case!(spawn, "spawn.exe", "failing maybe SIGCHLD related");
        test_case!(
            spawn_static,
            "spawn-static.exe",
            "failing maybe SIGCHLD related"
        );
        test_case!(popen, "popen.exe", SKIP_UNTIL_SHARED_LIBRARY_IS_SUPPORTED);
        test_case!(
            popen_static,
            "popen-static.exe",
            SKIP_UNTIL_SHARED_LIBRARY_IS_SUPPORTED
        );
        test_case!(
            sigaltstack,
            "sigaltstack.exe",
            SKIP_UNTIL_BETTER_IDEA_NOT_TO_USE_TVOSR_DEFINED_SIGALTSTACK
        );
        test_case!(
            sigaltstack_static,
            "sigaltstack-static.exe",
            SKIP_UNTIL_BETTER_IDEA_NOT_TO_USE_TVOSR_DEFINED_SIGALTSTACK
        );
        test_case!(
            execle_env,
            "execle-env.exe",
            SKIP_UNTIL_SHARED_LIBRARY_IS_SUPPORTED
        );
        test_case!(
            execle_env_static,
            "execle-env-static.exe",
            SKIP_UNTIL_SHARED_LIBRARY_IS_SUPPORTED
        );
    }

    mod zig {
        use crate::nop::executable_path;
        use tempfile::tempdir;

        fn test_case_executable_path(test_case: &str) -> String {
            format!(
                "{}/{}",
                std::env::var("TVISOR_TEST_ZIG_CASES_DIR").unwrap(),
                test_case,
            )
        }

        fn run(path: String) {
            let binding = tempdir().unwrap();
            let tmp_dir = binding.path();

            let test_case = super::TestCase::default()
                .with_executable_path(executable_path().as_str())
                .with_args(path.as_str())
                .with_expected_exit_code(0)
                .with_cwd(tmp_dir.to_str().unwrap())
                .with_expected_output("TODO");
            test_case.run();
        }

        #[test]
        #[ignore]
        fn musl() {
            run(test_case_executable_path("musl"));
        }

        #[test]
        #[ignore]
        fn gnu() {
            run(test_case_executable_path("gnu"));
        }
    }
}
