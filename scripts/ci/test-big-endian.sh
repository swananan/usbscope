#!/bin/sh
# Exercise the real big-endian CLI with the existing independent Python/TShark
# fixtures, before the kernel matrix runs its live-capture suites.
set -eu
repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repo_dir"
export USBSCOPE_BE_SYSROOT="${USBSCOPE_BE_SYSROOT:-$repo_dir/target/vm-guest/aarch64_be}"
export USBSCOPE_BE_BINARY="${USBSCOPE_BE_BINARY:-$repo_dir/target/aarch64_be-unknown-linux-gnu/release/usbscope}"
export USBSCOPE_BE_QEMU="${USBSCOPE_BE_QEMU:-qemu-aarch64_be}"
test -f "$USBSCOPE_BE_BINARY"
wrapper=$(mktemp "$repo_dir/target/usbscope-be-cli.XXXXXX")
trap 'rm -f "$wrapper"' EXIT HUP INT TERM
cat > "$wrapper" <<'WRAPPER'
#!/bin/sh
exec "$USBSCOPE_BE_QEMU" -L "$USBSCOPE_BE_SYSROOT" "$USBSCOPE_BE_BINARY" "$@"
WRAPPER
chmod +x "$wrapper"
python3 tests/e2e.py --binary "$wrapper" --require-tshark
