# usbscope

English | [简体中文](README.zh-CN.md)

[![checks](https://github.com/swananan/usbscope/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/swananan/usbscope/actions/workflows/ci.yml)
[![build](https://github.com/swananan/usbscope/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/swananan/usbscope/actions/workflows/build.yml)
[![kernel e2e](https://github.com/swananan/usbscope/actions/workflows/vm-e2e.yml/badge.svg?branch=main)](https://github.com/swananan/usbscope/actions/workflows/vm-e2e.yml)

**Capture USB requests on Linux without usbmon, then inspect them in Wireshark.**

usbscope is an eBPF-based command-line tool built for a specific need: capturing
USB traffic when **the kernel was built without `CONFIG_USB_MON`**. It records
host-side USB requests (URBs) to help troubleshoot devices, drivers, and USB audio.

[Download a build](docs/downloads.md) · [Start capturing](docs/usage.md#live-capture) ·
[Check requirements](docs/usage.md#requirements-and-minimum-kernel-version)

## What you can do

- **Inspect captures in Wireshark.** Save USB requests, completions, and errors as pcapng files.
- **Focus on the traffic you need.** Use tcpdump-inspired options and USB filters for devices, endpoints, transfer types, payloads, and latency.
- **Capture full payloads.** No application-imposed length truncation; read failures and resource exhaustion are reported as capture loss.
- **Investigate USB audio.** Preserve per-frame information for isochronous (ISO) transfers and view frame errors and completion-gap statistics.

Saved captures can also be filtered offline, and output files can be rotated.
See the [usage guide](docs/usage.md) for examples.

## Supported environments

| Item | Support and validation |
| --- | --- |
| Platform | Linux x86_64 (little endian) or arm64 (little or big endian). See the [big-endian kernel restrictions](docs/big-endian.md). |
| Kernel | **Lowest tested version: Linux 6.6.142.** Compatibility follows the [tested kernel configurations](docs/ci.md); older versions remain unverified. |
| Kernel features | Built-in USB core (`CONFIG_USB=y`), kernel BTF, and BPF/tracing support. Works with or without `CONFIG_USB_MON`. |
| Live-capture access | Root, readable kernel BTF, and access to the required kernel symbol addresses. |
| Tested page sizes | x86_64: 4 KiB; arm64: 4 KiB and 64 KiB. arm64 16 KiB pages remain unverified. |

Supports **eBPF CO-RE** across the tested kernels within each architecture and
byte order. Prebuilt packages are statically linked: the capture machine does
not need Rust, LLVM, libbpf, or libpcap installed.

Live capture is currently validated in QEMU; physical USB controllers still
need validation. This tool observes host-side requests, not electrical bus
transactions. See the [full requirements](docs/usage.md#requirements-and-minimum-kernel-version)
and [capture limits](docs/usage.md#current-usage-limits) for details.

**Offline reading only needs the executable and a capture file** on a supported
platform; root, kernel BTF, USB hardware, and the BPF object are not required.

## Documentation

| Task | Guide |
| --- | --- |
| Get a runnable package | [Downloads and runtime dependencies](docs/downloads.md) |
| Capture and analyze USB traffic | [Commands, offline reading, rotation, and audio](docs/usage.md) · [Filter reference](docs/filters.md) |
| Check compatibility | [Requirements and limits](docs/usage.md#requirements-and-minimum-kernel-version) · [Platform coverage](docs/platforms.md) · [Big-endian support](docs/big-endian.md) |
| Build or contribute | [Build and test guide](docs/development.md) |
| Understand the implementation | [Aya/Rust, CO-RE, ring buffer, and capture hooks](docs/architecture.md) |
| See how capture is tested | [Kernel CI matrix](docs/ci.md) · [tcpdump/usbmon and TShark comparisons](docs/usbmon-comparison.md) |
| Follow development | [Implementation stages and validation](docs/implementation.md) |

Licensed under **MIT OR Apache-2.0**. See [licensing](docs/licensing.md#english)
for component licenses and distribution details.
