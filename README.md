# usbscope

English | [简体中文](README.zh-CN.md)

usbscope is an eBPF-based USB capture CLI for the **niche case where the Linux
kernel was built without `CONFIG_USB_MON`**. It records host-side USB requests
(URBs) to help diagnose device, driver, and USB audio problems without usbmon.

## What it does

- Captures USB payloads without an application-imposed length cap and reports capture loss explicitly.
- Provides tcpdump-inspired commands and USB filters for devices, endpoints, transfer types, payloads, and latency.
- Writes Wireshark-compatible pcapng files, replays saved captures, and rotates output files.
- Preserves ISO frame metadata and provides statistics for USB audio analysis.

## Supported environments

| Requirement | Support |
| --- | --- |
| Operating system and CPU | Linux, little-endian x86_64 and arm64 (aarch64). No 32-bit ARM, Windows, or macOS support. |
| Kernel | **Minimum validated: Linux 6.6.142.** See the [tested configurations](docs/ci.md#validation-status). |
| Page size | x86_64: 4 KiB; arm64: 4 KiB or 64 KiB. |
| Kernel configuration | Built-in USB core (`CONFIG_USB=y`), kernel BTF, and BPF/tracing support. `CONFIG_USB_MON` is optional. |
| Live-capture access | Root, readable kernel BTF, and access to the required kernel symbol addresses. |
| Cross-kernel compatibility | Supports **eBPF CO-RE** within each supported CPU architecture. |

Linux 5.17 is the upstream feature floor, **not a validated minimum**; 5.17 through
earlier 6.6 releases remain unverified. Current live-capture validation uses QEMU;
physical USB controllers still need validation. Read the [full requirements and
limits](docs/usage.md) before deploying. Offline reading does not require live-capture
privileges, kernel BTF, USB hardware, or a BPF object.

## Documentation

| Topic | Guide |
| --- | --- |
| Getting started and capture commands | [Usage, filters, offline reading, rotation, and audio](docs/usage.md) |
| Compatibility and limitations | [Runtime requirements](docs/usage.md#requirements-and-minimum-kernel-version) · [Usage limits](docs/usage.md#current-usage-limits) |
| Filter reference | [USB filter grammar](docs/filters.md) |
| Building and testing | [Toolchains, packaging, and e2e tests](docs/development.md) |
| Implementation | [Aya/Rust, CO-RE, ring buffer, and capture hooks](docs/architecture.md) |
| Platform support | [Architecture coverage, cross-compilation, and ARM tests](docs/platforms.md) |
| Kernel CI and capture comparison | [Kernel matrix](docs/ci.md) · [tcpdump/usbmon and TShark validation](docs/usbmon-comparison.md) |
| Development record | [Implementation stages and validation evidence](docs/implementation.md) |
| License | [MIT OR Apache-2.0 and component licenses](docs/licensing.md#english) |
