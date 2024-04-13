use std::env::var;

fn main() {
    let mut compiler = cc::Build::new();
    let arch = var("TARGET")
        .map(|target| {
            if target.contains("aarch64") {
                "aarch64"
            } else if target.contains("x86_64") {
                compiler.file("asm/sigreturn_x86_64.S");
                "x86_64"
            } else {
                panic!("unsupported target {:?}", target)
            }
        })
        .unwrap();

    compiler.file(format!("asm/entry_{}.S", arch));
    compiler.file(format!("asm/start_guest_main_thread_{}.S", arch));
    compiler.file(format!("asm/clone_kernel_thread_{}.S", arch));
    compiler.file(format!("asm/start_guest_child_thread_{}.S", arch));
    compiler.compile("tvisor_asm.o");

    println!(
        "cargo:rerun-if-changed={}/asm",
        var("CARGO_MANIFEST_DIR").unwrap()
    );

    // Linker flags to make the binary run on the top of the 128TiB address.
    // For some reason, `cargo test` on x86_64-none-unknown crashes with PIE.
    // TODO: investigate why.
    println!("cargo:rustc-link-arg=-no-pie");
    println!("cargo:rustc-link-arg=--image-base");
    println!("cargo:rustc-link-arg=0x100000000000");
}
