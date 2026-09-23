# usbscope

[English](README.md) | 简体中文

[![checks](https://github.com/swananan/usbscope/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/swananan/usbscope/actions/workflows/ci.yml)
[![build](https://github.com/swananan/usbscope/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/swananan/usbscope/actions/workflows/build.yml)
[![kernel e2e](https://github.com/swananan/usbscope/actions/workflows/vm-e2e.yml/badge.svg?branch=main)](https://github.com/swananan/usbscope/actions/workflows/vm-e2e.yml)

**在没有 usbmon 的 Linux 上抓取 USB 请求，用 Wireshark 分析。**

usbscope 是一个基于 eBPF 的 USB 抓包命令行工具，专为 **Linux 内核编译时未启用
`CONFIG_USB_MON`** 的小众场景设计。它记录主机侧 USB 请求（URB），帮助排查设备、
驱动和 USB 音频传输问题。

[下载预编译包](docs/downloads.zh-CN.md) · [开始抓包](docs/usage.zh-CN.md#实时抓包) ·
[检查运行要求](docs/usage.zh-CN.md#运行要求与最低内核版本)

## 能帮你做什么

- **用 Wireshark 分析抓包。** 将 USB 请求、完成事件和错误保存为 pcapng 文件。
- **找到关心的流量。** 使用接近 tcpdump 的命令参数，按设备、端点、传输类型、载荷和延迟过滤。
- **保留完整载荷。** 不人为截断 USB payload；读取失败或资源不足时明确报告抓取丢失。
- **排查 USB 音频问题。** 保留等时（ISO）传输的逐帧信息，统计帧错误和完成事件的时间间隔。

还可以离线筛选已保存的抓包，并按大小或时间轮转输出文件。具体示例见[使用指南](docs/usage.zh-CN.md)。

## 支持环境

| 项目 | 支持与验证情况 |
| --- | --- |
| 平台 | Linux x86_64（小端）或 arm64（小端或大端）。大端有额外的[内核版本限制](docs/big-endian.zh-CN.md)。 |
| 内核 | **最低已验证版本：Linux 6.6.142。** 兼容范围以[已测试的内核配置（英文）](docs/ci.md)为准；更早版本尚未验证。 |
| 内核功能 | USB 核心编译进内核（`CONFIG_USB=y`），具备内核 BTF 和 BPF/跟踪功能。`CONFIG_USB_MON` 可开可关。 |
| 实时抓包权限 | root 权限、可读的内核 BTF，以及所需内核符号地址的访问权限。 |
| 已验证页大小 | x86_64：4 KiB；arm64：4 KiB 和 64 KiB。arm64 的 16 KiB 页尚未验证。 |

支持 **eBPF CO-RE**，同一架构和字节序的程序可用于已验证的不同内核。
预编译包采用静态链接，抓包机器无需安装 Rust、LLVM、libbpf 或 libpcap。

当前实时抓包验证基于 QEMU，实体 USB 控制器仍待验证。工具观察的是主机侧请求，
不记录 USB 总线上的电气事务。详细条件见[完整运行要求](docs/usage.zh-CN.md#运行要求与最低内核版本)
和[抓包限制](docs/usage.zh-CN.md#当前使用限制)。

**离线读取只需可执行文件和抓包文件**，在受支持的平台上无需 root 权限、内核 BTF、
USB 硬件或 BPF 目标文件。

## 文档索引

| 想做什么 | 从这里开始 |
| --- | --- |
| 获取可运行的程序 | [下载与运行依赖](docs/downloads.zh-CN.md) |
| 抓包与分析 | [命令示例、离线读取、轮转与音频](docs/usage.zh-CN.md) · [过滤器参考（英文）](docs/filters.md) |
| 确认兼容性 | [运行要求与限制](docs/usage.zh-CN.md#运行要求与最低内核版本) · [平台覆盖（英文）](docs/platforms.md) · [大端支持](docs/big-endian.zh-CN.md) |
| 构建或参与开发 | [构建与测试指南](docs/development.zh-CN.md) |
| 了解实现 | [Aya/Rust、CO-RE、ring buffer 与挂载点](docs/architecture.zh-CN.md) |
| 查看测试方式 | [内核 CI 矩阵（英文）](docs/ci.md) · [tcpdump/usbmon 与 TShark 对比（英文）](docs/usbmon-comparison.md) |
| 查看开发进展 | [实现阶段与验证记录（英文）](docs/implementation.md) |

采用 **MIT OR Apache-2.0** 许可证，组件许可与分发说明见[许可证文档](docs/licensing.md#简体中文)。
