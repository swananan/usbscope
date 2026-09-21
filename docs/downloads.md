# Downloads and runtime dependencies

[README](../README.md) · English | [简体中文](downloads.zh-CN.md)

## Download a build

Open the [build workflow](https://github.com/swananan/usbscope/actions/workflows/build.yml),
select a successful run for the desired commit, and download the matching item
under **Artifacts**. Each item contains a `.tar.gz` archive and its `.sha256` file.

| Linux target | Artifact / archive stem |
| --- | --- |
| x86_64, little endian | `usbscope-x86_64-linux` |
| arm64, little endian | `usbscope-aarch64-linux` |
| arm64, big endian | `usbscope-aarch64_be-linux` |

After unpacking the downloaded artifact ZIP, verify and extract the archive.
For x86_64:

```sh
sha256sum --check usbscope-x86_64-linux.tar.gz.sha256
tar -xzf usbscope-x86_64-linux.tar.gz
cd usbscope-x86_64-linux
sha256sum --check SHA256SUMS
./usbscope --help
sudo ./usbscope -i any --duration 30 -w capture.pcapng --fail-on-loss
```

Keep `usbscope` and `usbscope.bpf.o` in the same directory. The archive also
includes documentation and licenses. ARM executables use 64 KiB segment
alignment for both supported page sizes. CLI debug information is removed from
the archive; the original build output keeps it. The BPF object's BTF and CO-RE
relocations are preserved.

## What the capture machine needs

All three packaged CLIs are **statically linked**, including the C runtime.
They have no ELF dynamic loader or `DT_NEEDED` shared libraries. You do not need
to install Rust, Clang, LLVM, bpf-linker, libbpf, libpcap, or a matching shared
libc to run the package. Wireshark/TShark is optional for viewing the output;
usbscope itself does not invoke either program.

Live capture uses the adjacent BPF object and the host's kernel BTF, tracing
support, kernel configuration, and privileges described in the
[runtime requirements](usage.md#requirements-and-minimum-kernel-version).
Offline replay only needs the executable and input file.

## Build CI

The independent [build workflow](../.github/workflows/build.yml) runs on pushes
to `main`, `v*` tags, pull requests, and manual dispatch. Its three parallel jobs
produce the archives above; artifacts are retained for 30 days. The final `build`
check requires every target to pass. It uploads Actions artifacts without
creating or publishing a GitHub Release.

Each job checks the executable's architecture, byte order, absence of a dynamic
loader/shared libraries, and ARM page alignment. It checks the BPF architecture,
byte order, BTF, CO-RE relocations, checksums, and executable mode. It then extracts
the actual archive into a fresh directory and runs all CLI/TShark e2e cases.
ARM binaries execute through qemu-user with an empty target sysroot.

These jobs build the CLI and BPF object without building a kernel, BusyBox,
libpcap, tcpdump, or the VM fixtures. QEMU and TShark are test tools on CI runners.
Live USB capture remains covered by the separate [kernel matrix](ci.md), which
uses the same package script.

For local builds, see the [build guide](development.md) and
[big-endian toolchain setup](big-endian.md#build-on-x86_64-linux).
Packaging requires Python 3 and the matching GCC/binutils and libc development
files in addition to the pinned Rust/BPF toolchains. The build script selects
Rust's [`crt-static` target feature](https://doc.rust-lang.org/reference/linkage.html#static-and-dynamic-c-runtimes)
and verifies the resulting ELF. `scripts/ci/test-package.sh <arch>` repeats the
archive checks and CLI e2e locally; it requires TShark and qemu-user for ARM.
