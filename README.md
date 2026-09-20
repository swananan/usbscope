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
