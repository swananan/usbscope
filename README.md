# usbscope

usbscope is an eBPF-based USB capture CLI for Linux kernels built without
`CONFIG_USB_MON`. It targets this niche debugging scenario, with tcpdump-inspired
commands, USB-aware filters, and Wireshark-compatible capture files.

The implementation is being built in stages. See [the implementation plan](docs/implementation.md)
for completed work, validation, and remaining limitations. Live capture is not yet available.

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

## Kernel development tests

The tested BPF build uses Rust `nightly-2025-12-01` (with `rust-src`),
`bpf-linker 0.9.15`, and Clang 18. The C shim compiles to LLVM bitcode and is
linked with the Rust program; no C compiler or libbpf is needed at capture time.
`BPF_TOOLCHAIN`, `BPF_LINKER`, and `BPF_CLANG` override build tools.

```sh
sh scripts/build-ebpf.sh
sh tests/vm/build-kernel.sh /path/to/linux-source
python3 tests/vm/run.py
```

The VM runner needs QEMU x86_64, a static BusyBox, GCC, cpio, and a Linux source
tree. It uses TCG, so host root and KVM are unnecessary. The guest checks that
usbmon is disabled, attaches a real probe, triggers a USB descriptor request,
and compares captured metadata with an independent usbfs result. A successful
attach without a matching event fails the test. Logs are in `target/vm-e2e.log`.
