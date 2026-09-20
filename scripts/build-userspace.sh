#!/bin/sh
# ARM big endian is a Rust tier-3 target: build its standard library as well.
set -eu
repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_dir"
capture_arch=${1:?usage: build-userspace.sh ARCH [cargo build options]}
shift
case "$capture_arch" in
    arm64) capture_arch=aarch64 ;;
    arm64_be) capture_arch=aarch64_be ;;
esac
case "$capture_arch" in
    x86_64)
        export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="${CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER:-${CROSS_COMPILE:-x86_64-linux-gnu-}gcc}"
        export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS="${CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS:-} -C target-feature=+crt-static"
        ;;
    aarch64)
        export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER:-${CROSS_COMPILE:-aarch64-linux-gnu-}gcc}"
        export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS="${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS:-} -C target-feature=+crt-static -C link-arg=-Wl,-z,max-page-size=65536"
        ;;
    aarch64_be)
        export CARGO_TARGET_AARCH64_BE_UNKNOWN_LINUX_GNU_LINKER="${CARGO_TARGET_AARCH64_BE_UNKNOWN_LINUX_GNU_LINKER:-${CROSS_COMPILE:-aarch64_be-buildroot-linux-gnu-}gcc}"
        # The SDK's shared loader assumes 4 KiB pages. Static binaries aligned
        # to 64 KiB also run on 4 KiB kernels and need no foreign runtime libc.
        export CARGO_TARGET_AARCH64_BE_UNKNOWN_LINUX_GNU_RUSTFLAGS="${CARGO_TARGET_AARCH64_BE_UNKNOWN_LINUX_GNU_RUSTFLAGS:-} -C target-feature=+crt-static -C link-arg=-Wl,-z,max-page-size=65536"
        # Older Rust stdarch miscompiles big-endian NEON string searches used by
        # object/Aya. Keep this separately pinned from the BPF toolchain.
        exec cargo +"${BE_TOOLCHAIN:-nightly-2026-09-18}" build --locked \
            --target aarch64_be-unknown-linux-gnu -Z build-std "$@"
        ;;
    *) printf 'Unsupported userspace architecture: %s\n' "$capture_arch" >&2; exit 1 ;;
esac
exec cargo build --locked --target "$capture_arch-unknown-linux-gnu" "$@"
