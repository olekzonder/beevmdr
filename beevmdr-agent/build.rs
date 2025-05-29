use std::env;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/ebpf/beevmdr.bpf.c";

fn main() {
    println!("Build script is running!");

    let out_dir = env::var_os("OUT_DIR").expect("OUT_DIR must be set");
    let mut out_path = PathBuf::from(out_dir);
    out_path.push("beevmdr.skel.rs");

    let arch = env::var("CARGO_CFG_TARGET_ARCH")
        .expect("CARGO_CFG_TARGET_ARCH must be set");

    let include_path = Path::new("ebpf").join(arch);

    SkeletonBuilder::new()
        .source(SRC)
        .clang_args([
            OsStr::new("-I"),
            include_path.as_os_str(),
        ])
        .build_and_generate(&out_path)
        .expect("bpf compilation failed");

    println!("cargo:rerun-if-changed={}", SRC);
}