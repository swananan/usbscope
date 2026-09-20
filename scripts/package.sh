#!/bin/sh
set -eu
repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_dir"
capture_arch=${1:-$(uname -m)}
case "$capture_arch" in
    arm64) capture_arch=aarch64 ;;
    arm64_be) capture_arch=aarch64_be ;;
    x86_64|aarch64|aarch64_be) ;;
    *) printf 'Supported release architectures: x86_64, aarch64, aarch64_be\n' >&2; exit 1 ;;
esac
platform="$capture_arch-linux"
rust_target="$capture_arch-unknown-linux-gnu"
scripts/build-userspace.sh "$capture_arch" --release
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
