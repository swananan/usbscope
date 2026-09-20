#!/bin/sh
# Test fresh extraction of the actual downloadable archive, including its modes.
set -eu
repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repo_dir"
capture_arch=${1:?usage: test-package.sh x86_64|aarch64|aarch64_be}
case "$capture_arch" in
    x86_64|aarch64|aarch64_be) ;;
    *) exit 1 ;;
esac
archive="usbscope-$capture_arch-linux.tar.gz"
(cd target/dist && sha256sum --check "$archive.sha256")
work=$(mktemp -d "$repo_dir/target/package-test-$capture_arch.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
tar -xzf "target/dist/$archive" -C "$work"
package="$work/usbscope-$capture_arch-linux"
python3 scripts/ci/release.py "$capture_arch" "$package"
export USBSCOPE_TEST_BINARY="$package/usbscope"
binary="$USBSCOPE_TEST_BINARY"
if [ "$capture_arch" != x86_64 ] || [ "$(uname -m)" != x86_64 ]; then
    export USBSCOPE_TEST_QEMU="${USBSCOPE_TEST_QEMU:-qemu-$capture_arch}"
    export USBSCOPE_TEST_EMPTY_ROOT="$work/empty-sysroot"
    mkdir "$USBSCOPE_TEST_EMPTY_ROOT"
    binary="$work/run-usbscope"
    cat > "$binary" <<'WRAPPER'
#!/bin/sh
exec "$USBSCOPE_TEST_QEMU" -L "$USBSCOPE_TEST_EMPTY_ROOT" "$USBSCOPE_TEST_BINARY" "$@"
WRAPPER
    chmod +x "$binary"
fi
"$binary" --version
python3 tests/e2e.py --binary "$binary" --require-tshark
