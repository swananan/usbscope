# Linux architecture support

usbscope supports **x86_64 (little endian) and arm64 (little or big endian)**.
The CLI, its libraries, and the BPF object must match the target architecture
and byte order. CO-RE adapts
kernel structure layouts within an architecture; it does not change probe
register conventions or byte order. The loader rejects mismatched BPF architecture, endian, or
configuration ABI metadata before attaching anything.

## Runtime coverage

| Target | Kernel coverage | Bulk SG requirements |
| --- | --- | --- |
| x86_64 | 6.6.142, 6.8, 6.12.110, 6.18.52, 7.2.6; 4 KiB pages | SPARSEMEM_VMEMMAP; readable `vmemmap_base` and `page_offset_base` symbol addresses |
| arm64 little endian | 6.6.142/6.8 with 4 KiB and 64 KiB; 6.12.110 with 4 KiB; 6.18.52/7.2.6 with 64 KiB | SPARSEMEM_VMEMMAP; readable running kernel configuration; tested with `CONFIG_ARM64_VA_BITS=48` |
| arm64 big endian | 6.6.142 with 4 KiB; 6.12.110 with 64 KiB | Same ARM SG requirements; see [big-endian kernel restrictions](big-endian.md) |

arm64 reads `/proc/config.gz`, falling back to `/boot/config-$(uname -r)` if the
proc file cannot be opened. It checks the configured page size against the
running system's page size. The C accessor combines these settings with CO-RE
`sizeof(struct page)` to calculate the linear mapping, following the
[arm64 kernel memory definitions](https://github.com/torvalds/linux/blob/v6.8/arch/arm64/include/asm/memory.h).
Upstream [Linux 6.9 changed vmemmap placement](https://github.com/torvalds/linux/commit/32697ff38287bb9f6c7ee1b04656a677b62496a6).
The loader selects the old/new formula from the running release, because these
preprocessor constants are absent from BTF. Vendor backports of that change under
older release numbers require separate validation. Additional tested kernels and
page sizes are recorded in the [CI guide](ci.md).
No kernel headers or compiler are needed on a capture host. Missing/unsupported
configuration disables SG capture; affected transfers are explicitly reported
as incomplete, and `--fail-on-loss` fails. Contiguous-buffer capture remains
available. Tagged KASAN SG memory is unsupported.

The ARM tests use QEMU's `virt` machine, TCG, and a virtual xHCI controller.
USB_MON-disabled capture and independent tcpdump comparison have passed in the
[recorded configurations](ci.md#validation-status). The same arm64 BPF object, per byte order, works across the tested page
sizes and kernels. Linux 6.8 with 64 KiB pages also passed with kernel pointer
authentication enabled. Physical ARM controllers, kernel BTI, 16 KiB pages,
other VA widths, and tagged KASAN still need validation. See the
[usage limits](usage.md#current-usage-limits) for the remaining USB/audio limitations.
32-bit ARM, other big-endian architectures, Windows, and macOS are outside the
current support scope.

## Build and package

On a native x86_64 or little-endian arm64 Linux machine, install the
[build toolchains](development.md#build-and-test), then run:

```sh
scripts/build-ebpf.sh
scripts/package.sh
```

The BPF output is `target/<arch>/usbscope.bpf.o`. A native build also refreshes
`target/usbscope.bpf.o` for development. Cross builds leave that native copy
alone. `arm64` is accepted as an alias for `aarch64` by the build/package scripts;
`arm64_be` aliases `aarch64_be`. Big-endian builds use a separate Rust/SDK setup:
see the [big-endian build and test guide](big-endian.md).

Cross-building ARM releases on an x86_64 Ubuntu host additionally needs
`gcc-aarch64-linux-gnu` and the Rust target:

```sh
rustup target add aarch64-unknown-linux-gnu
scripts/package.sh aarch64
```

The archives are `target/dist/usbscope-<arch>-linux.tar.gz`, where `<arch>` is
`x86_64`, `aarch64`, or `aarch64_be`. Each contains the CLI, matching BPF
object, English/Chinese READMEs, detailed documentation, licenses, and checksums.
These are Linux GNU builds; little-endian libc requirements follow the
compiler/sysroot, while the big-endian CLI is statically linked.
Keep the executable and object together when installing the archive.

## ARM e2e from an x86_64 host

In addition to the [build tools](development.md#build-and-test), install `qemu-system-arm`,
`gcc-aarch64-linux-gnu`, and `ubuntu-keyring`. The helper below downloads
signature-verified Ubuntu 24.04 arm64 packages into an isolated directory and
extracts them there. It does not install packages into the host system and does
not need root. Guest libraries are resolved from that directory using ELF
metadata; no foreign binary is executed on the host.

```sh
rustup target add aarch64-unknown-linux-gnu
scripts/build-ebpf.sh aarch64
python3 tests/vm/prepare-guest.py --arch aarch64
ARCH=arm64 tests/vm/build-kernel.sh /path/to/linux-source target/vm-kernel-arm64
python3 tests/vm/run.py --arch aarch64 --release --live --audio --filters --sg \
  --guest-root target/vm-guest/aarch64 \
  --kernel target/vm-kernel-arm64/arch/arm64/boot/Image \
  --log target/vm-arm64.log --artifacts target/vm-arm64-artifacts
```

For a 64 KiB page kernel, use `ARM64_PAGE_SIZE=64K` when building. The page size
affects the test kernel, not the userspace or BPF build. Use `USBMON=y` and
`--compare-tcpdump` for the independent comparison. Keep kernel build directories
separate for each version, page size, and USB_MON setting, and finish each kernel
build before starting its VM suite.

On a native arm64 host, omit `--guest-root`; the runner uses matching host
binaries and libraries. `--arch` defaults to the host architecture. To exercise
an extracted release, pass `--binary /path/to/usbscope` and
`--bpf-object /path/to/usbscope.bpf.o`.

## Regular regression coverage

The VM workflow defines 16 PR/main jobs and 52 nightly/full jobs across
x86_64/4 KiB and arm64/4 KiB/64 KiB in both byte orders where the pinned kernel
supports them, with USB_MON disabled/enabled.
The [CI guide](ci.md) lists the pinned kernels and reproduction commands. ARM jobs run on
x86_64 hosts using the same cross-build and rootless QEMU path tested locally.
They exercise packaged binaries, control and bulk traffic, SG buffers, 137
sparse ISO frames, filters, full 2,097,664-byte payloads, and strict loss handling.
The loss test sizes its ring to one guest page and pauses the consumer while
generating traffic, so it also works with 64 KiB pages.

The suite rejects wrong-architecture, wrong-endian, and incompatible-ABI objects before
attachment, replays raw archives inside the guest, and compares guest/host
pcapng filtering byte for byte. USB_MON-enabled jobs additionally compare against
tcpdump and run the corrupted-capture checks, with separate contiguous-buffer
and SG/audio cases. Local results are recorded in [implementation.md](implementation.md);
the expanded hosted workflow has not yet been run. Each architecture/endian target's packaged
CLI and BPF object are reused across all kernels; cached kernel bundles contain
the matching ISO fixture, so test jobs do not rebuild the BPF object or CLI.
