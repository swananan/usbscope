# usbscope

[English](README.md) | 简体中文

usbscope 是一个基于 eBPF 的 USB 抓包命令行工具，面向 **Linux 内核编译时未启用
`CONFIG_USB_MON` 的小众场景**。它不依赖 usbmon，记录主机侧 USB 请求（URB），
帮助排查 USB 设备、驱动和音频传输问题。

## 能做什么

- 抓取 USB 载荷，不人为设置长度截断上限，并明确报告抓取丢失。
- 提供参考 tcpdump 设计的命令参数，按设备、端点、传输类型、载荷和延迟过滤。
- 输出 Wireshark 可读取的 pcapng 文件，支持离线回放和文件轮转。
- 保留 ISO 帧元数据，提供 USB 音频分析所需的统计信息。

## 支持环境

| 要求 | 支持范围 |
| --- | --- |
| 操作系统与 CPU | Linux，小端 x86_64 和 arm64（aarch64）。不支持 32 位 ARM、Windows 或 macOS。 |
| 内核 | **最低已验证版本：Linux 6.6.142。** 具体配置见[验证记录（英文）](docs/ci.md#validation-status)。 |
| 页大小 | x86_64：4 KiB；arm64：4 KiB 或 64 KiB。 |
| 内核配置 | USB 核心编译进内核（`CONFIG_USB=y`），具备内核 BTF 和 BPF/跟踪功能。`CONFIG_USB_MON` 可开可关。 |
| 实时抓包权限 | root 权限、可读的内核 BTF，以及所需内核符号地址的访问权限。 |
| 跨内核兼容 | 支持在同一受支持 CPU 架构内使用 **eBPF CO-RE**。 |

Linux 5.17 只是上游内核的功能门槛，**不是最低已验证版本**；从 5.17 到早期 6.6
仍未验证。当前实时抓包验证基于 QEMU，实体 USB 控制器仍需验证。部署前请阅读
[完整运行要求与使用限制](docs/usage.zh-CN.md)。离线读取不需要实时抓包权限、内核 BTF、
USB 硬件或 BPF 目标文件。

## 文档索引

| 主题 | 文档 |
| --- | --- |
| 入门与抓包命令 | [使用方法、过滤、离线读取、轮转与音频](docs/usage.zh-CN.md) |
| 兼容性与限制 | [运行要求](docs/usage.zh-CN.md#运行要求与最低内核版本) · [使用限制](docs/usage.zh-CN.md#当前使用限制) |
| 过滤器参考 | [USB 过滤语法（英文）](docs/filters.md) |
| 构建与测试 | [工具链、打包与 e2e 测试](docs/development.zh-CN.md) |
| 实现细节 | [Aya/Rust、CO-RE、ring buffer 与挂载点](docs/architecture.zh-CN.md) |
| 平台支持 | [架构覆盖、交叉编译与 ARM 测试（英文）](docs/platforms.md) |
| 内核 CI 与抓包对比 | [内核矩阵（英文）](docs/ci.md) · [tcpdump/usbmon 与 TShark 验证（英文）](docs/usbmon-comparison.md) |
| 开发记录 | [实现阶段与验证证据（英文）](docs/implementation.md) |
| 许可证 | [MIT OR Apache-2.0 及组件许可证](docs/licensing.md#简体中文) |
