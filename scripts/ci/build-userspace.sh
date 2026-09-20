#!/bin/bash
# Build each architecture's release and VM helpers once for the whole matrix.
set -euo pipefail
cd "$(dirname "$0")/../.."
capture_arch=${1:?usage: build-userspace.sh x86_64|aarch64|aarch64_be}
case "$capture_arch" in
    x86_64|aarch64|aarch64_be) ;;
    *) exit 1 ;;
esac
rust_target="$capture_arch-unknown-linux-gnu"
bundle="target/ci/userspace/$capture_arch"
if [[ "$capture_arch" = aarch64_be ]]; then
    python3 tests/vm/prepare-big-endian.py --output "$bundle/guest-root"
    # shellcheck disable=SC1091
    source target/be-tools/environment.sh
fi
scripts/package.sh "$capture_arch"
scripts/build-userspace.sh "$capture_arch" --release --example probe-smoke
mkdir -p "$bundle"
cp "target/$rust_target/release/examples/probe-smoke" "$bundle/"
if [[ "$capture_arch" != "$(uname -m)" && "$capture_arch" != aarch64_be ]]; then
    python3 tests/vm/prepare-guest.py --arch "$capture_arch" --output "$bundle/guest-root"
fi
# Preserve executable modes and symlinks when passing through Actions artifacts.
tar --exclude='./guest-root/.apt' -C "$bundle" -czf "target/dist/vm-tools-$capture_arch.tar.gz" .
