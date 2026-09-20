# usbscope

usbscope is an eBPF-based USB capture CLI for Linux kernels built without
`CONFIG_USB_MON`. It targets this niche debugging scenario, with tcpdump-inspired
commands, USB-aware filters, and Wireshark-compatible capture files.

Live control, bulk, interrupt, and ISO capture is implemented, including x86_64
bulk scatter-gather buffers. See [implementation and validation](docs/implementation.md)
for the completed stages, test evidence, and remaining limitations. The tested
baseline is little-endian x86_64 Linux 6.6.142 and 6.8 with `CONFIG_USB_MON=n`.

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

`scripts/package.sh` builds an x86_64 Linux archive in `target/dist/`, containing
the CLI, BPF object, documentation, licenses, and binary/object SHA-256 checksums.
Keep `usbscope` and `usbscope.bpf.o` together after extraction. The CLI locates the
adjacent object automatically, regardless of the working directory. This is a
native Linux build; libc requirements follow the build host.

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
`-B` configures ring capacity in KiB, not packet length. Capture needs kernel
BTF, BPF tracing/JIT, kprobes, readable kernel symbol addresses, and sufficient
privileges (root in the development setup). The BPF object is searched for beside
the executable, falling back to `target/usbscope.bpf.o`, and can be supplied with
`--bpf-object`.

IN data is copied at `usb_unanchor_urb` only when its immediate caller is
`__usb_hcd_giveback_urb`, after DMA unmapping/copyback and before the driver
callback. A missing required hook or redacted symbol addresses is a startup
error. This hook ordering is kernel-internal and requires regression coverage.
At stop, new submissions are disabled, with a 200 ms completion drain. URBs
still in flight at that boundary are reported separately from transport loss.

Bulk SG buffers are supported on x86_64 SPARSEMEM_VMEMMAP kernels exposing
`vmemmap_base` and `page_offset_base`. Addresses and structure sizes are resolved
at runtime; no fixed kernel layout or DMA-to-CPU address conversion is assumed.
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

The VM runner needs QEMU x86_64, a static BusyBox, GCC, cpio, and a Linux source
tree. It uses TCG, so host root and KVM are unnecessary. The guest checks that
usbmon is disabled, attaches a real probe, triggers a USB descriptor request,
and compares captured metadata with an independent usbfs result. A successful
attach without a matching event fails the test. Logs are in `target/vm-e2e.log`.
The live suite adds 2 MiB + 512 byte USB storage reads and writes, unique URB
pairing, exact payload comparison, byte-identical archive replay, TShark decoding,
and an intentionally undersized ring that must report loss and fail strict mode.
Artifacts are retained under `target/vm-artifacts`.
The audio suite builds a VM-only test driver against the chosen kernel and
verifies a 137-frame sparse ISO transfer against independent driver results.

For independent live capture comparison, build an additional kernel with usbmon
enabled and run with `--compare-tcpdump`. The [comparison guide](docs/usbmon-comparison.md)
explains synchronization, field/payload matching, and explicit handling of
usbmon/libpcap truncation. It also documents the negative tests for the checker.

GitHub Actions runs userspace checks and defines a four-job VM matrix for
6.6.142 and 6.8, each with USB_MON disabled and enabled. The enabled jobs add
independent tcpdump capture comparison, including separate contiguous bulk runs.
The comparison suites have passed locally on both kernels; the hosted workflow
has not yet been run. Physical USB controllers, DMA bounce paths, live ISO IN,
and aarch64 still need hardware/architecture
coverage. Capture is implemented for interrupt URBs, but the VM fixtures exercise
control, bulk, and ISO traffic.
