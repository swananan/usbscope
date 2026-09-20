# Usage guide

[README](../README.md) · English | [简体中文](usage.zh-CN.md)

Download a [platform package](downloads.md) or follow the
[build guide](development.md#build-and-test) to obtain the CLI and BPF object.
The examples below run from the repository root or use `usbscope` from your `PATH`.

[Requirements](#requirements-and-minimum-kernel-version) · [Limits](#current-usage-limits) ·
[Capture semantics](#capture-semantics) · [Live capture](#live-capture) ·
[Offline reading and rotation](#offline-reading-and-file-rotation) · [Filters](#filters) ·
[ISO and audio](#iso-and-audio)

## Requirements and minimum kernel version

**Minimum upstream kernel feature requirement: Linux 5.17**, because the BPF
program requires [`bpf_loop`](https://github.com/torvalds/linux/blob/v5.17/kernel/bpf/bpf_iter.c#L681).
Earlier upstream kernels need a backport of that helper. Helper availability
alone is insufficient to establish compatibility with this program.

**Minimum validated kernel: Linux 6.6.142.** Tested platforms are
**x86_64 (little endian) and arm64 (little or big endian)**, including 4 KiB and
64 KiB pages on arm64. [Big-endian support](big-endian.md) has additional kernel restrictions.
See the [CI guide](ci.md) for the kernel matrix and
the exact configurations validated locally. Versions outside those results,
including 5.17 through earlier 6.6 releases, remain unverified.
Use the validated versions as the current deployment baseline and check the
following requirements for live capture:

| Requirement | Current restriction |
| --- | --- |
| Platform | Linux x86_64, arm64 little endian (`aarch64`), or arm64 big endian (`aarch64_be`). CLI and BPF object must match both architecture and byte order. 32-bit ARM and other operating systems are not supported. |
| USB core | Built into the kernel (`CONFIG_USB=y`). The current loader resolves USB hooks from vmlinux BTF; loading their BTF from a USB core module is not implemented. `CONFIG_USB_MON` is optional. |
| Kernel BTF | Readable `/sys/kernel/btf/vmlinux`, with type/function information for the USB hooks (`CONFIG_DEBUG_INFO_BTF`). |
| BPF and tracing | BPF syscall/JIT, ringbuf, `bpf_loop`, fentry/fexit, and kprobes must be available. See the [VM kernel configuration](../tests/vm/build-kernel.sh) for the tested configuration. |
| Kernel symbols | Readable, nonzero addresses for the required functions in `/proc/kallsyms`. Redacted symbols prevent startup. |
| Privileges | Live capture is tested as root. Kernel security policy must permit BPF tracing and kernel symbol access; restricted containers or kernel lockdown can prevent capture. |
| arm64 SG configuration | Readable `/proc/config.gz` or `/boot/config-$(uname -r)` matching the running kernel. SG translation uses the page size and `CONFIG_ARM64_VA_BITS`; missing or unsupported configuration disables SG capture and affected events are reported as loss. |

Offline reading with `-r` does not load BPF programs and does not need these
live-capture privileges, kernel BTF, USB hardware, or a BPF object.

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

See [implementation and validation](implementation.md) for the evidence and
[the filter grammar](filters.md) for supported fields and missing-data rules.

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

At stop, observation of new submissions is disabled, with a 200 ms completion drain. URBs
still in flight at that boundary are reported separately from transport loss.

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
fields remain unknown to filters. ISO completions can be read without their
submissions, including sparse frames and empty tail frames; actual transferred
bytes are not treated as the original buffer's extent.

`-C` uses decimal megabytes; `-G` uses capture timestamps. Both rotate between
whole events, so a large event can exceed the size target. Files are named
`capture.pcapng.000000`, `.000001`, and so on. `-W` stops at the file count rather
than overwriting earlier files, and existing rotated paths are rejected. Raw
archives remain one continuous file and are not rotated with the pcapng output.

Logs and statistics go to stderr, including when `-w -` writes binary data to
stdout. Raw archives retain kernel loss counters on an orderly stop, including
loss of entire events whose first ring record never arrived. An abrupt process
termination can prevent that final counter snapshot from being written.

## Filters

```sh
sudo target/release/usbscope -w capture.pcapng 'vid 0x1234 and bulk and in'
target/release/usbscope -r capture.usbraw -w slow.pcapng 'event complete and latency > 2ms'
target/release/usbscope -d 'bus 1 or payload contains 0x55534243'
```

The [USB filter grammar](filters.md) supports boolean combinations, numeric
comparisons, masks, control setup fields, streaming payload searches, and latency.
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
