#!/bin/sh
set -eu
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_dir"
case $(uname -m) in
    x86_64) platform=x86_64-linux ;;
    *) printf 'Release artifacts currently target tested x86_64 Linux only\n' >&2; exit 1 ;;
esac
cargo build --release --locked
scripts/build-ebpf.sh
artifact_dir="$repo_dir/target/dist/usbscope-$platform"
mkdir -p "$artifact_dir/docs"
cp target/release/usbscope target/usbscope.bpf.o README.md LICENSE-MIT LICENSE-APACHE "$artifact_dir/"
cp docs/filters.md docs/implementation.md docs/usbmon-comparison.md "$artifact_dir/docs/"
(
    cd "$artifact_dir"
    sha256sum usbscope usbscope.bpf.o > SHA256SUMS
)
tar -C "$repo_dir/target/dist" -czf "$repo_dir/target/dist/usbscope-$platform.tar.gz" "usbscope-$platform"
printf 'Artifact: %s/target/dist/usbscope-%s.tar.gz\n' "$repo_dir" "$platform"
