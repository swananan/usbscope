# usbscope

usbscope is an eBPF-based USB capture CLI for Linux kernels built without
`CONFIG_USB_MON`. It targets this niche debugging scenario, with tcpdump-inspired
commands, USB-aware filters, and Wireshark-compatible capture files.

The implementation is being built in stages. See [the implementation plan](docs/implementation.md)
for completed work, validation, and remaining limitations. Live control, bulk,
interrupt, and ISO capture is available for contiguous URB buffers on tested kernels.

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

## Development

```sh
cargo build
cargo test --workspace
python3 tests/e2e.py --binary target/debug/usbscope --require-tshark
```

The first e2e tests independently produce transport archives, invoke the CLI,
and use TShark to verify USB fields and payload bytes. They require Python 3;
`--require-tshark` makes a missing external decoder a failure rather than a skip.

```sh
usbscope -r capture.usbraw -w capture.pcapng --fail-on-loss
```

Logs and statistics go to stderr, including when `-w -` writes binary data to stdout.

## Live capture

```sh
sudo target/debug/usbscope -D
sudo target/debug/usbscope -i usb2 --device 2 -w capture.pcapng
sudo target/debug/usbscope -i any --duration 30 --raw-output capture.usbraw -w capture.pcapng --fail-on-loss
```

Without `-w`, the CLI prints an event summary. `-c` counts complete events;
`-B` configures ring capacity in KiB, not packet length. Capture needs kernel
BTF, BPF tracing/JIT, kprobes, readable kernel symbol addresses, and sufficient
privileges (root in the development setup). The current baseline is Linux 6.6,
little-endian x86_64. The BPF object defaults to `target/usbscope.bpf.o` and can
be supplied with `--bpf-object`.

IN data is copied at `usb_unanchor_urb` only when its immediate caller is
`__usb_hcd_giveback_urb`, after DMA unmapping/copyback and before the driver
callback. A missing required hook or redacted symbol addresses is a startup
error. This hook ordering is kernel-internal and requires regression coverage.
At stop, new submissions are disabled, with a 200 ms completion drain. URBs
still in flight at that boundary are reported separately from transport loss.

Scatter-gather buffers are not supported at this stage; they are reported
explicitly and make `--fail-on-loss` fail.

## Filters

```sh
sudo target/debug/usbscope -w capture.pcapng 'vid 0x1234 and bulk and in'
target/debug/usbscope -r capture.usbraw -w slow.pcapng 'event complete and latency > 2ms'
target/debug/usbscope -d 'bus 1 or payload contains 0x55534243'
```

The [USB filter grammar](docs/filters.md) supports boolean combinations, numeric
comparisons, masks, control setup fields, streaming payload searches, and latency.
Safe necessary predicates run in BPF; exact matching runs after reassembly.
`-F` reads a filter file. `-s 0` is accepted for compatibility and always means
full payload capture. Other snap lengths are rejected.

## ISO and audio

```sh
sudo target/debug/usbscope -i usb1 -w audio.pcapng --iso-stats --device-context devices.json
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

The tested BPF build uses Rust `nightly-2025-12-01` (with `rust-src`),
`bpf-linker 0.9.15`, and Clang 18. The C shim compiles to LLVM bitcode and is
linked with the Rust program; no C compiler or libbpf is needed at capture time.
`BPF_TOOLCHAIN`, `BPF_LINKER`, and `BPF_CLANG` override build tools.

```sh
sh scripts/build-ebpf.sh
sh tests/vm/build-kernel.sh /path/to/linux-source
python3 tests/vm/run.py
python3 tests/vm/run.py --live
python3 tests/vm/run.py --live --audio
python3 tests/vm/run.py --live --audio --filters
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
