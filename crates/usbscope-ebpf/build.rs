use std::{env, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rustc-check-cfg=cfg(bpf_target_arch, values(\"x86_64\", \"aarch64\"))");
    let arch = env::var("AYA_BPF_TARGET_ARCH").unwrap_or_else(|_| env::consts::ARCH.to_owned());
    assert!(
        matches!(arch.as_str(), "x86_64" | "aarch64"),
        "unsupported BPF target architecture"
    );
    println!("cargo:rustc-cfg=bpf_target_arch=\"{arch}\"");
    println!("cargo:rerun-if-env-changed=AYA_BPF_TARGET_ARCH");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let source =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("../../core-shims/usb.c");
    let bitcode = out.join("usb.bc");
    let clang = env::var_os("BPF_CLANG").unwrap_or_else(|| "clang".into());
    let status = Command::new(clang)
        .args([
            "-target",
            "bpfel",
            "-mcpu=v3",
            "-O2",
            "-g",
            "-emit-llvm",
            "-c",
            "-Wall",
            "-Werror",
        ])
        .arg(if arch == "aarch64" {
            "-DUSBSCOPE_ARM64=1"
        } else {
            "-DUSBSCOPE_X86_64=1"
        })
        .arg(&source)
        .arg("-o")
        .arg(&bitcode)
        .status()
        .expect("run Clang for CO-RE accessors");
    assert!(status.success(), "CO-RE accessor compilation failed");
    println!("cargo:rustc-link-arg={}", bitcode.display());
    println!("cargo:rustc-link-arg=--btf");
    println!("cargo:rerun-if-changed={}", source.display());
    println!("cargo:rerun-if-env-changed=BPF_CLANG");
}
