# ARM big-endian support

[README](../README.md) · English | [简体中文](big-endian.zh-CN.md)

The big-endian target is Linux **arm64**, named `aarch64_be` in build and VM
commands (`arm64_be` is also accepted by build/package scripts). This does not
claim support for s390x, PowerPC, or 32-bit ARM. The matching CLI and `bpfeb`
object are required for live capture; little-endian ARM uses `aarch64`/`bpfel`.

## Kernel boundary

The matrix includes big-endian 4 KiB and 64 KiB kernels with USB_MON disabled and
enabled for **6.6.142, 6.6.157, 6.8, and 6.12.110**. Local validation and hosted
matrix coverage are distinguished in the [CI results](ci.md#validation-status).
The existing requirements for BTF, USB hooks, VA48, and SPARSEMEM_VMEMMAP apply.

The pinned **6.18.52 and 7.2.6** sources make `CPU_BIG_ENDIAN` depend on `BROKEN`.
These entries remain little-endian-only. The builder does not override `BROKEN`
or patch the kernel to enable them. See the upstream
[arm64 Kconfig](https://github.com/torvalds/linux/blob/v6.18/arch/arm64/Kconfig)
and the explicit capability flags in [kernels.json](../scripts/ci/kernels.json).

## Build on x86_64 Linux

To build only the release, install the [BPF tools](development.md#build-and-test),
`build-essential`, Python 3, curl, and xz-utils. The helper downloads a
SHA-256-pinned Bootlin SDK without installing foreign packages into the host
system or requiring root.

```sh
rustup toolchain install nightly-2026-09-18 --component rust-src
python3 tests/vm/prepare-big-endian.py --toolchain-only
. target/be-tools/environment.sh
scripts/package.sh aarch64_be
```

To test the extracted package, install `qemu-user` and TShark and run
`scripts/ci/test-package.sh aarch64_be`; no guest libraries are needed.
VM tests additionally need `flex`, `bison`, `pkg-config`, `file`,
`qemu-system-arm`, and `cpio`. Run `python3 tests/vm/prepare-big-endian.py`
without `--toolchain-only` to build their guest tools.

The archive is `target/dist/usbscope-aarch64_be-linux.tar.gz`. Keep the CLI and
BPF object together. The BPF toolchain remains `nightly-2025-12-01`, Clang 18,
and `bpf-linker 0.9.15`. Big-endian userspace separately uses
`nightly-2026-09-18` and `-Z build-std`, because Rust supplies no prebuilt standard
library for this target. The older nightly produced incorrect ARM big-endian
NEON string searches during ELF parsing in local tests. `BE_TOOLCHAIN` overrides
the userspace pin; alternatives require the same e2e validation.

The SDK is Bootlin `aarch64be--glibc--stable-2025.08-1` (GCC 14.3, glibc 2.41).
The CLI and guest executables are statically linked with 64 KiB segment alignment
so they run with either tested page size. The SDK's shared loader only works with
4 KiB pages. Rustix uses its libc backend on this target. Kernel gzip decoding
uses flate2's zlib-rs backend to avoid crc32fast's native-word ARM CRC byte-order
assumption; a gzip vector from Python checks both decoding and checksum rejection.

The guest helper builds BusyBox 1.37.0, libpcap 1.10.4, and tcpdump 4.99.5.
libpcap matches the little-endian baseline: 1.10.5 produced ISO submissions with
`caplen > len` in testing because its original length omitted the descriptors.
The comparison keeps its strict packet-length checks. Sources and digests are
recorded in [prepare-big-endian.py](../tests/vm/prepare-big-endian.py).

## Regular e2e and local reproduction

The kernel workflow's build job runs unit tests and all 23 CLI/TShark cases through
`qemu-aarch64_be`. Kernel jobs boot a big-endian kernel and independently assert
both the executing process's byte order and `CONFIG_CPU_BIG_ENDIAN=y`.
They use the ordinary USB fixtures, including full 2,097,664-byte IN/OUT payloads,
SG buffers, 137 sparse ISO frames, filters, forced loss, and incorrect-object
rejection. USB_MON-enabled jobs also require SG/audio and contiguous-buffer
tcpdump comparisons and the corruption checks.

To run the same packaged-artifact path as CI, prepare the
[kernel build dependencies](ci.md#local-reproduction-and-updates), then:

```sh
env -u CROSS_COMPILE scripts/ci/build-userspace.sh x86_64
scripts/ci/build-userspace.sh aarch64_be
. target/be-tools/environment.sh
JOBS=4 python3 scripts/ci/kernel.py build --version 6.12.110 \
  --arch aarch64_be --pages 64K --usbmon y
scripts/ci/run-vm.sh aarch64_be 6.12.110 64K y
```

Use separate kernel bundles/build directories for different configurations.
The same big-endian BPF object is reused across kernels and page sizes.

## File compatibility

Ring records, `.usbraw` archives, build metadata, and generated pcapng remain
little endian on every host; USB payload/setup bytes are copied verbatim. Map
values and kernel structure reads use native byte order. The raw archive ABI
stays at version 1. Existing little-endian readers can consume big-endian hosts'
captures. VM tests replay archives on the big-endian guest and little-endian
host, then compare pcapng and filtered output byte for byte. The independent
tcpdump reader also handles big-endian pcap headers and USB pseudoheaders.
