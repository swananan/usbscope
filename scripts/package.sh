#!/bin/sh
set -eu
repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_dir"
capture_arch=${1:-$(uname -m)}
case "$capture_arch" in
    arm64) capture_arch=aarch64 ;;
    x86_64|aarch64) ;;
    *) printf 'Supported release architectures: x86_64, aarch64\n' >&2; exit 1 ;;
esac
platform="$capture_arch-linux"
rust_target="$capture_arch-unknown-linux-gnu"
if [ "$capture_arch" != "$(uname -m)" ]; then
    case "$capture_arch" in
        aarch64)
            export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER:-aarch64-linux-gnu-gcc}"
            ;;
        x86_64)
            export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="${CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER:-x86_64-linux-gnu-gcc}"
            ;;
    esac
fi
cargo build --release --locked --target "$rust_target"
scripts/build-ebpf.sh "$capture_arch"
artifact_dir="$repo_dir/target/dist/usbscope-$platform"
mkdir -p "$artifact_dir/docs"
cp "target/$rust_target/release/usbscope" "target/$capture_arch/usbscope.bpf.o" README.md README.zh-CN.md LICENSE-MIT LICENSE-APACHE "$artifact_dir/"
cp docs/*.md "$artifact_dir/docs/"
(
    cd "$artifact_dir"
    sha256sum usbscope usbscope.bpf.o > SHA256SUMS
)
tar -C "$repo_dir/target/dist" -czf "$repo_dir/target/dist/usbscope-$platform.tar.gz" "usbscope-$platform"
printf 'Artifact: %s/target/dist/usbscope-%s.tar.gz\n' "$repo_dir" "$platform"
