#!/bin/sh
set -eu
repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_dir"
capture_arch=${1:-${AYA_BPF_TARGET_ARCH:-$(uname -m)}}
case "$capture_arch" in
    arm64) capture_arch=aarch64 ;;
    arm64_be) capture_arch=aarch64_be ;;
    x86_64|aarch64|aarch64_be) ;;
    *) printf 'Unsupported BPF architecture: %s\n' "$capture_arch" >&2; exit 1 ;;
esac
export AYA_BPF_TARGET_ARCH="${capture_arch%_be}"
case "$capture_arch" in
    aarch64_be) bpf_target=bpfeb-unknown-none ;;
    *) bpf_target=bpfel-unknown-none ;;
esac
export CARGO_TARGET_DIR="$repo_dir/target/ebpf/$capture_arch"
export RUSTFLAGS="-C debuginfo=2 -C target-cpu=v3 -C linker=${BPF_LINKER:-bpf-linker}"
cargo +"${BPF_TOOLCHAIN:-nightly-2025-12-01}" build \
    --manifest-path crates/usbscope-ebpf/Cargo.toml --target "$bpf_target" \
    -Z build-std=core --release --locked
mkdir -p "$repo_dir/target/$capture_arch"
cp "$CARGO_TARGET_DIR/$bpf_target/release/usbscope-ebpf" "$repo_dir/target/$capture_arch/usbscope.bpf.o"
# Preserve the native development path without letting a cross build replace it.
if [ "$capture_arch" = "$(uname -m)" ]; then
    cp "$repo_dir/target/$capture_arch/usbscope.bpf.o" "$repo_dir/target/usbscope.bpf.o"
fi
printf 'BPF object: %s/target/%s/usbscope.bpf.o\n' "$repo_dir" "$capture_arch"
