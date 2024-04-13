use std::path::Path;

fn main() {
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    // depending on the carg target, create a target for zig cc:
    let (zig_target, zig_target_freestanding) = match arch.as_str() {
        "x86_64" => ("x86_64-linux-musl", "x86_64-freestanding-none"),
        "aarch64" => ("aarch64-linux-musl", "aarch64-freestanding-none"),
        _ => panic!("unsupported target"),
    };

    // Check cases/arch directory:
    let cases_dir = std::fs::read_dir(format!("c/{arch}"));
    if cases_dir.is_err() {
        // Create cases/arch directory:
        std::fs::create_dir(format!("c/{arch}")).unwrap()
    }

    // Search all *.c files in the cases/ directory and compile them with zig cc:
    for entry in std::fs::read_dir("c").unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            continue;
        }
        let ext = path.extension().unwrap();
        if ext == "c" {
            // Create the output path in cases/${arch}/${file_name without extension}:
            let exe_path_str =
                format!("c/{}/{}", arch, path.file_stem().unwrap().to_str().unwrap());
            let exe_path = Path::new(exe_path_str.as_str());

            // Check if the source file is newer than the executable, and if not, skip it:
            // Instead of add arch as a extension, add arch as a subdirectory:
            if exe_path.exists() {
                let exe_metadata = exe_path.metadata().unwrap();
                let src_metadata = path.metadata().unwrap();
                if exe_metadata.modified().unwrap() > src_metadata.modified().unwrap() {
                    continue;
                }
            }

            // Compile the file with zig cc.
            let mut cmd = std::process::Command::new("zig");
            cmd.arg("cc")
                .arg("-target")
                .arg(zig_target)
                .arg("-g")
                .arg("-static")
                .arg("-O0")
                .arg("-o")
                .arg(exe_path)
                .arg(path);
            println!("running: {:?}", cmd);
            let status = cmd.status().unwrap();
            assert!(status.success());
        } else if ext == "S" {
            // The assembly file is in the format of foo_${arch}.S, so we need to check if ${arch} matches.
            let file_name_without_ext = path.file_stem().unwrap().to_str().unwrap();
            // Check if the file name matches the arch with arch variable.
            if !file_name_without_ext.contains(arch.as_str()) {
                continue;
            }

            let file_name_without_arch = file_name_without_ext
                .trim_end_matches(arch.as_str())
                .trim_end_matches('_');

            // Create the output path in cases/${arch}/${file_name without extension}:
            let exe_path_str = format!("c/{}/{}", arch, file_name_without_arch,);
            let exe_path = Path::new(exe_path_str.as_str());

            // Check if the source file is newer than the executable, and if not, skip it:
            // Instead of add arch as a extension, add arch as a subdirectory:
            if exe_path.exists() {
                let exe_metadata = exe_path.metadata().unwrap();
                let src_metadata = path.metadata().unwrap();
                if exe_metadata.modified().unwrap() > src_metadata.modified().unwrap() {
                    continue;
                }
            }

            // Compile the file with zig cc.
            let mut cmd = std::process::Command::new("zig");
            cmd.arg("cc")
                .arg("-target")
                .arg(zig_target_freestanding)
                .arg("-g")
                .arg("-static")
                .arg("-o")
                .arg(exe_path)
                .arg(path);
            println!("running: {:?}", cmd);
            let status = cmd.status().unwrap();
            assert!(status.success());
        }
    }

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();

    // Rerun always if ../tvisor directory changes.
    println!("cargo:rerun-if-changed={manifest_dir}/../tvisor");
    let tvisor_fs_executable =
        format!("{manifest_dir}/../tvisor/target/{arch}-unknown-none/debug/tvisor-fs",);
    let tvisor_nop_executable =
        format!("{manifest_dir}/../tvisor/target/{arch}-unknown-none/debug/tvisor-nop",);
    // Also check the existence of the executable.
    if !Path::new(&tvisor_fs_executable).exists() {
        panic!("tvisor-fs executable not found: {}", tvisor_fs_executable);
    }
    let c_test_cases_dir = format!("{}/c", manifest_dir);
    let zig_test_cases_dir = format!("{}/zig", manifest_dir);
    let musl_libc_test_cases_dir = format!("{}/musl-libc", manifest_dir);
    // Run always if the test cases directory changes.
    println!("cargo:rerun-if-changed={c_test_cases_dir}");
    println!("cargo:rerun-if-changed={zig_test_cases_dir}");

    println!("cargo:rustc-env=TVISOR_TEST_C_CASES_DIR={c_test_cases_dir}/{arch}");
    println!("cargo:rustc-env=TVISOR_TEST_ZIG_CASES_DIR={zig_test_cases_dir}/{arch}");
    println!("cargo:rustc-env=TVISOR_TEST_MUSL_LIBC_CASES_DIR={musl_libc_test_cases_dir}/{arch}");
    println!("cargo:rustc-env=TVISOR_FS_EXECUTABLE={tvisor_fs_executable}");
    println!("cargo:rustc-env=TVISOR_NOP_EXECUTABLE={tvisor_nop_executable}");
}
