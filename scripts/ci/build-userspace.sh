#!/bin/bash
# Build each architecture's release and VM helpers once for the whole matrix.
set -euo pipefail
cd "$(dirname "$0")/../.."
capture_arch=${1:?usage: build-userspace.sh x86_64|aarch64}
case "$capture_arch" in
    x86_64|aarch64) ;;
    *) exit 1 ;;
esac
rust_target="$capture_arch-unknown-linux-gnu"
if [[ "$capture_arch" != "$(uname -m)" ]]; then
    case "$capture_arch" in
        aarch64) export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER:-aarch64-linux-gnu-gcc} ;;
        x86_64) export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=${CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER:-x86_64-linux-gnu-gcc} ;;
    esac
fi
scripts/package.sh "$capture_arch"
cargo build --release --locked --target "$rust_target" --example probe-smoke
bundle="target/ci/userspace/$capture_arch"
mkdir -p "$bundle"
cp "target/$rust_target/release/examples/probe-smoke" "$bundle/"
if [[ "$capture_arch" != "$(uname -m)" ]]; then
    python3 tests/vm/prepare-guest.py --arch "$capture_arch" --output "$bundle/guest-root"
fi
# Preserve executable modes and symlinks when passing through Actions artifacts.
tar --exclude='./guest-root/.apt' -C "$bundle" -czf "target/dist/vm-tools-$capture_arch.tar.gz" .
