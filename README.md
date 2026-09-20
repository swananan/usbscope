# usbscope

English | [简体中文](README.zh-CN.md)

usbscope is an eBPF-based USB capture CLI for the **niche case where the Linux
kernel was built without `CONFIG_USB_MON`**. It provides tcpdump-inspired
commands, USB-aware filters, and Wireshark-compatible capture files without
depending on usbmon.

Built with **Aya and Rust eBPF**, it supports **eBPF CO-RE (Compile Once, Run
Everywhere)** through small C accessors and transports capture records through
a **BPF ring buffer**. Control, bulk, interrupt, and ISO capture is implemented,
including bulk scatter-gather buffers on **Linux x86_64 and arm64 (aarch64)**.

## Requirements and minimum kernel version

**Minimum upstream kernel feature requirement: Linux 5.17**, because the BPF
program requires [`bpf_loop`](https://github.com/torvalds/linux/blob/v5.17/kernel/bpf/bpf_iter.c#L681).
Earlier upstream kernels need a backport of that helper. Helper availability
alone is insufficient to establish compatibility with this program.

**Minimum validated kernel: Linux 6.6.142.** The current e2e matrix covers
**6.6.142 and 6.8 on little-endian x86_64 and arm64**, with 4 KiB and 64 KiB
pages on arm64. Compatibility with other versions,
including 5.17 through earlier 6.6 releases and newer kernels, remains unverified.
Use the validated versions as the current deployment baseline and check the
following requirements for live capture:

| Requirement | Current restriction |
| --- | --- |
| Platform | Linux, little-endian x86_64 or arm64 (aarch64). Each architecture has its own CLI and BPF object. 32-bit ARM and other operating systems are not supported. |
| USB core | Built into the kernel (`CONFIG_USB=y`). The current loader resolves USB hooks from vmlinux BTF; loading their BTF from a USB core module is not implemented. `CONFIG_USB_MON` is optional. |
| Kernel BTF | Readable `/sys/kernel/btf/vmlinux`, with type/function information for the USB hooks (`CONFIG_DEBUG_INFO_BTF`). |
| BPF and tracing | BPF syscall/JIT, ringbuf, `bpf_loop`, fentry/fexit, and kprobes must be available. See the [VM kernel configuration](tests/vm/build-kernel.sh) for the tested configuration. |
| Kernel symbols | Readable, nonzero addresses for the required functions in `/proc/kallsyms`. Redacted symbols prevent startup. |
| Privileges | Live capture is tested as root. Kernel security policy must permit BPF tracing and kernel symbol access; restricted containers or kernel lockdown can prevent capture. |
| arm64 SG configuration | Readable `/proc/config.gz` or `/boot/config-$(uname -r)` matching the running kernel. SG translation uses the page size and `CONFIG_ARM64_VA_BITS`; missing or unsupported configuration disables SG capture and affected events are reported as loss. |

Offline reading with `-r` does not load BPF programs and does not need these
live-capture privileges, kernel BTF, USB hardware, or a BPF object.

## eBPF CO-RE support

Clang emits BTF CO-RE relocations for kernel field offsets and type sizes from
the C accessors. `bpf-linker` links them into the Rust BPF object, and Aya applies
the relocations using the running kernel's BTF at load time. For each supported
architecture, the **same BPF object has passed e2e tests on Linux 6.6.142 and 6.8**.
On compatible kernels of the target architecture, this avoids recompiling for
each kernel layout. Capture hosts do not need kernel headers, Clang, or libbpf.
Objects are specific to the CPU architecture because probe register conventions
differ; the CLI rejects an object built for the wrong architecture or
configuration ABI before loading it.

CO-RE handles structure layout changes. The required BPF helpers, attachable USB
functions, and their execution order must still be present. The completion hook
depends on kernel-internal behavior, so additional kernel versions/configurations
need regression testing before compatibility can be claimed.

## Current usage limits

- **Observation level:** events describe host-side URB submissions, completions,
  and submission errors. Electrical USB transactions, wire timing, and bus-level
  retries are outside this capture model.
- **Capture completeness:** payload length and ISO descriptor counts have no
  application-imposed snap limit. Ring capacity, pending-event state, temporary
  storage, disk space, and reader/format limits still apply. Read failures and
  resource exhaustion are reported as loss; `--fail-on-loss` makes them an error.
- **SG buffers:** require SPARSEMEM_VMEMMAP. x86_64 uses 4 KiB pages and visible
  `vmemmap_base`/`page_offset_base` symbols. arm64 is validated with 4 KiB/64 KiB
  pages and `CONFIG_ARM64_VA_BITS=48`; it additionally needs the running kernel
  configuration. ISO SG buffers, other memory models, and arm64 tagged KASAN
  memory are unsupported. arm64 16 KiB pages and other VA widths remain unverified.
- **Validation coverage:** live control, contiguous/SG bulk, and ISO OUT have
  QEMU e2e coverage. Physical controllers, DMA bounce paths, live ISO IN,
  interrupt traffic, separately allocated SG chains, enqueue failures, and
  physical arm64 devices still need validation.
- **Audio context:** the device JSON is an initial sysfs snapshot. Configuration
  and alternate-setting changes over time, UAC feedback decoding, and PCM/WAV
  export are not implemented.

See [implementation and validation](docs/implementation.md) for the evidence and
[the filter grammar](docs/filters.md) for supported fields and missing-data rules.

## Capture semantics

The observation unit is a USB Request Block (URB) submission, completion, or
submission error. This is a host-side software trace, not an electrical bus trace.
Payloads have no application-imposed snap length: transport records are chunked,
then reassembled. Resource exhaustion and inaccessible buffers are reported as
capture loss, never disguised as complete data.

Standard output files use pcapng with `LINKTYPE_USB_LINUX_MMAPPED` (220), including
ISO descriptors and their original offsets. Wireshark has its own per-record
limits (currently 128 MiB for USB); chunked raw archives retain the original
transport events independently of that reader limit.

## Build and test

Userspace Rust is pinned to 1.98.1. The BPF build uses Rust
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
`target/aarch64/usbscope.bpf.o`. See the [platform guide](docs/platforms.md)
for native/cross builds and ARM e2e commands.

## Offline reading and file rotation

```sh
usbscope -r capture.usbraw -w capture.pcapng --fail-on-loss
usbscope -r capture.pcapng -w selected.pcapng 'bulk and in'
sudo usbscope -i any -w capture.pcapng -C 100 -W 10
sudo usbscope -i usb1 -w audio.pcapng -G 60 --iso-stats
```

`-r` recognizes raw archives and pcapng Enhanced Packet Blocks with
`LINKTYPE_USB_LINUX_MMAPPED` (220). Classic pcap and other packet/link types are
not supported. Reading streams large payloads through temporary storage. Input
snap truncation is reported as incomplete data. Standard USB pcapng lacks VID/PID;
completion request lengths and latency also need an observed submission. Missing
fields remain unknown to filters.

`-C` uses decimal megabytes; `-G` uses capture timestamps. Both rotate between
whole events, so a large event can exceed the size target. Files are named
`capture.pcapng.000000`, `.000001`, and so on. `-W` stops at the file count rather
than overwriting earlier files, and existing rotated paths are rejected. Raw
archives remain one continuous file and are not rotated with the pcapng output.

Logs and statistics go to stderr, including when `-w -` writes binary data to
stdout. Raw archives retain kernel loss counters on an orderly stop, including
loss of entire events whose first ring record never arrived. An abrupt process
termination can prevent that final counter snapshot from being written.

## Live capture

```sh
target/release/usbscope -D
sudo target/release/usbscope -i usb2 --device 2 -w capture.pcapng
sudo target/release/usbscope -i any --duration 30 --raw-output capture.usbraw -w capture.pcapng --fail-on-loss
```

Without `-w`, the CLI prints an event summary. `-c` counts complete events;
`-B` configures ring capacity in KiB, not packet length. The BPF object is searched
for beside the executable, falling back to `target/usbscope.bpf.o`, and can be
supplied with `--bpf-object`.

IN data is copied at `usb_unanchor_urb` only when its immediate caller is
`__usb_hcd_giveback_urb`, after DMA unmapping/copyback and before the driver
callback. A missing required hook or redacted symbol addresses is a startup
error. This hook ordering is kernel-internal and requires regression coverage.
At stop, observation of new submissions is disabled, with a 200 ms completion drain. URBs
still in flight at that boundary are reported separately from transport loss.

Bulk SG buffers are supported on x86_64 and arm64 SPARSEMEM_VMEMMAP kernels.
x86_64 reads `vmemmap_base` and `page_offset_base`; arm64 derives the mapping from
the running kernel configuration, page size, and CO-RE `struct page` size.
This translates CPU virtual memory rather than DMA addresses.
Unsupported memory models, ISO SG buffers, or unreadable memory are reported
explicitly and make `--fail-on-loss` fail.

## Filters

```sh
sudo target/release/usbscope -w capture.pcapng 'vid 0x1234 and bulk and in'
target/release/usbscope -r capture.usbraw -w slow.pcapng 'event complete and latency > 2ms'
target/release/usbscope -d 'bus 1 or payload contains 0x55534243'
```

The [USB filter grammar](docs/filters.md) supports boolean combinations, numeric
comparisons, masks, control setup fields, streaming payload searches, and latency.
Safe necessary predicates run in BPF; exact matching runs after reassembly.
`-F` reads a filter file. `-s 0` is accepted for compatibility and always means
full payload capture. Other snap lengths are rejected.

## ISO and audio

```sh
sudo target/release/usbscope -i usb1 -w audio.pcapng --iso-stats --device-context devices.json
```

Every ISO frame retains its status, original offset, and requested (submission)
or actual (completion) length. Only valid frame regions are copied; gaps are
zero-filled on export. Descriptor counts are not capped at 128. Statistics include
empty frames and errors as well as URB completion gaps, which are software
observations rather than exact bus timing.

The optional device JSON contains an initial passive sysfs snapshot, including
descriptor bytes. It is not a complete configuration/hotplug timeline and does
not automatically teach Wireshark a previously enumerated audio device. Capture
enumeration when class-specific decoding is needed. PCM/WAV extraction and UAC
feedback interpretation are not implemented.

## Kernel development tests

The C CO-RE shim compiles to LLVM bitcode and is linked with the Rust program;
no C compiler or libbpf is needed at capture time. Rust handles the probes,
capture policy, maps, and ring transport; C provides kernel structure access.
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
enabled and run with `--compare-tcpdump`. The [comparison guide](docs/usbmon-comparison.md)
explains synchronization, field/payload matching, and explicit handling of
usbmon/libpcap truncation. It also documents the negative tests for the checker.

GitHub Actions runs userspace checks and defines a twelve-job VM matrix:
x86_64, arm64/4 KiB, and arm64/64 KiB, each with 6.6.142 and 6.8 and USB_MON
disabled and enabled. The enabled jobs add
independent tcpdump capture comparison, including separate contiguous bulk runs.
The comparison suites have passed locally on both architectures and kernels; the hosted workflow
has not yet been run. The current validation boundaries are listed under
[usage limits](#current-usage-limits).

## License

Unless a file states otherwise, usbscope's source code and documentation are
available under either the [MIT License](LICENSE-MIT) or the
[Apache License 2.0](LICENSE-APACHE), at your option (`MIT OR Apache-2.0`).

The eBPF object retains its `Dual MIT/GPL` license declaration for
[GPL-compatible loading into the Linux kernel](https://docs.kernel.org/bpf/bpf_licensing.html).
The VM-only ISO test driver is separately licensed under
[GPL-2.0](tests/vm/kernel/COPYING). Third-party dependencies retain their
respective licenses.
