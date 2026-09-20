# Build and test guide

[README](../README.md) · English | [简体中文](development.zh-CN.md)

Run these commands from the repository root. Capture implementation and CO-RE
linking are described in the [architecture guide](architecture.md).

[Build and test](#build-and-test) · [Kernel development tests](#kernel-development-tests) ·
[Cross-compilation](platforms.md#build-and-package) · [Kernel CI](ci.md)

## Build and test

Little-endian userspace Rust is pinned to 1.98.1. Big-endian arm64 uses a
[separate nightly and cross SDK](big-endian.md). The BPF build uses Rust
`nightly-2025-12-01`, `bpf-linker 0.9.15`, and Clang 18. Install Clang 18 and
TShark through your system package manager, then build both components:

```sh
rustup toolchain install nightly-2025-12-01 --component rust-src
cargo +nightly-2025-12-01 install bpf-linker --version 0.9.15 --locked
cargo build --release --locked
scripts/build-ebpf.sh
cargo test --workspace --locked
python3 tests/e2e.py --binary target/release/usbscope --require-tshark
```

The CLI e2e tests independently produce transport archives, invoke the binary,
and use TShark to verify USB fields and payload bytes. They require Python 3;
`--require-tshark` makes a missing external decoder a failure rather than a skip.

`scripts/package.sh` builds a native x86_64 or aarch64 Linux archive in `target/dist/`, containing
the CLI, BPF object, documentation, licenses, and binary/object SHA-256 checksums.
Keep `usbscope` and `usbscope.bpf.o` together after extraction. The CLI locates the
adjacent object automatically, regardless of the working directory. This is a
Linux GNU build; libc requirements follow the selected compiler/sysroot.
On an x86_64 Linux build host, install `gcc-aarch64-linux-gnu` and cross-build with:

```sh
rustup target add aarch64-unknown-linux-gnu
scripts/package.sh aarch64
```

This produces `target/dist/usbscope-aarch64-linux.tar.gz`.
`scripts/build-ebpf.sh aarch64` builds only the ARM BPF object at
`target/aarch64/usbscope.bpf.o`. See the [platform guide](platforms.md)
for native/cross builds and ARM e2e commands.

## Kernel development tests

`BPF_TOOLCHAIN`, `BPF_LINKER`, and `BPF_CLANG` override build tools.

```sh
sh scripts/build-ebpf.sh
sh tests/vm/build-kernel.sh /path/to/linux-source
python3 tests/vm/run.py
python3 tests/vm/run.py --live
python3 tests/vm/run.py --live --audio
python3 tests/vm/run.py --live --audio --filters
python3 tests/vm/run.py --live --audio --filters --sg --release
```

The VM runner needs QEMU for the guest architecture, a matching BusyBox and
userspace libraries, GCC, cpio, and a Linux source tree. It supports native and
cross-architecture runs using TCG, so host root and KVM are unnecessary. The guest checks that
usbmon is disabled, attaches a real probe, triggers a USB descriptor request,
and compares captured metadata with an independent usbfs result. A successful
attach without a matching event fails the test. Logs are in `target/vm-e2e.log`.
The live suite adds 2 MiB + 512 byte USB storage reads and writes, unique URB
pairing, exact payload comparison, byte-identical archive replay, TShark decoding,
and an intentionally undersized ring that must report loss and fail strict mode.
It also rejects mismatched BPF objects and compares guest replay/filtering with
the host's results, including when their architectures differ.
Artifacts are retained under `target/vm-artifacts`.
The audio suite builds a VM-only test driver against the chosen kernel and
verifies a 137-frame sparse ISO transfer against independent driver results.

For independent live capture comparison, build an additional kernel with usbmon
enabled and run with `--compare-tcpdump`. The [comparison guide](usbmon-comparison.md)
explains synchronization, field/payload matching, and explicit handling of
usbmon/libpcap truncation. It also documents the negative tests for the checker.

GitHub Actions runs userspace checks and a tiered kernel matrix. PRs and pushes
to `main` run **16 VM jobs**: 6.6.142 and 6.18.52 on little-endian x86_64,
arm64/4 KiB, and arm64/64 KiB, plus big-endian ARM/4 KiB/64 KiB on 6.6.142,
all with USB_MON disabled and enabled. Nightly and default manual runs execute
**52 jobs**, adding 6.6.157, 6.8, 6.12.110, and 7.2.6; big endian is excluded
where the kernel requires `BROKEN`. Every enabled
job requires independent tcpdump comparison for both SG/audio and contiguous
bulk buffers. Each architecture/endian target builds its release and BPF object once for all
kernels. The stable `kernel-e2e` check requires every selected job to pass.

The [CI guide](ci.md) explains version pins, compact kernel caches, artifacts,
local reproduction, and recorded results. Hosted status and logs are available in
[GitHub Actions](https://github.com/swananan/usbscope/actions).
The current validation boundaries remain listed under [usage limits](usage.md#current-usage-limits).
