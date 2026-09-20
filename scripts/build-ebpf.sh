#!/bin/sh
set -eu
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_dir"
export CARGO_TARGET_DIR="$repo_dir/target/ebpf"
export RUSTFLAGS="-C debuginfo=2 -C target-cpu=v3 -C linker=${BPF_LINKER:-bpf-linker}"
cargo +"${BPF_TOOLCHAIN:-nightly-2025-12-01}" build \
    --manifest-path crates/usbscope-ebpf/Cargo.toml --target bpfel-unknown-none \
    -Z build-std=core --release --locked
cp "$CARGO_TARGET_DIR/bpfel-unknown-none/release/usbscope-ebpf" "$repo_dir/target/usbscope.bpf.o"
printf 'BPF object: %s/target/usbscope.bpf.o\n' "$repo_dir"
