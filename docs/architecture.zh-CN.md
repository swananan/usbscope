# 实现机制与 eBPF CO-RE

[README](../README.zh-CN.md) · [English](architecture.md) | 简体中文

本文说明抓包的实现机制。命令用法和运行限制见[使用指南](usage.zh-CN.md)，
构建工具和回归测试见[构建与测试指南](development.zh-CN.md)。

## 实现概览

项目采用 **Aya 和 Rust eBPF**，通过少量 C 访问函数支持 **eBPF CO-RE
（Compile Once, Run Everywhere，编译一次，到处运行）**，使用 **BPF ring buffer**
传输抓包记录。目前已实现控制（control）、批量（bulk）、中断（interrupt）和
等时（ISO）传输抓取，包括 **Linux x86_64 和 arm64（aarch64）** 上的
bulk scatter-gather（SG，分散/聚集）缓冲区。

C CO-RE shim 编译为 LLVM bitcode，再与 Rust 程序链接；抓包时不需要 C 编译器或 libbpf。
Rust 负责探针、抓包策略、BPF map 和 ring 传输，C 负责访问内核结构体。

## eBPF CO-RE 支持

Clang 根据 C 访问函数生成针对内核字段偏移和类型大小的 BTF CO-RE 重定位信息，
`bpf-linker` 将其链接进 Rust BPF 目标文件，Aya 则在加载时根据运行中内核的 BTF
完成重定位。x86_64 和 arm64 小端分别使用同一个 BPF 目标文件，通过了 Linux 6.6.142、
6.8、6.12.110、6.18.52 和 7.2.6 的 e2e 测试。arm64 大端使用独立的目标文件进行测试，
具体配置见 [CI 验证记录（英文）](ci.md#validation-status)。
对于目标架构上兼容的内核，无需针对每种内核结构布局重新编译。抓包主机不需要内核头文件、
Clang 或 libbpf。BPF 目标文件需要同时匹配 CPU 架构和字节序：小端使用 `bpfel`，
大端使用 `bpfeb`。CLI 会在加载前拒绝架构、字节序或配置 ABI 不匹配的文件。

CO-RE 处理的是结构体布局变化。所需的 BPF 辅助函数、可挂载的 USB 函数及其执行顺序仍须满足要求。
完成事件的挂载点依赖内核内部行为，因此其他内核版本或配置仍需通过回归测试后才能确认兼容性。

## 事件传输与过滤

载荷和 ISO 元数据通过 BPF ring buffer 分块传输，在用户态重组。程序不人为设置
载荷长度或 ISO 描述符数量的截断上限。完整性和格式限制见
[抓包语义](usage.zh-CN.md#抓包语义)与[使用限制](usage.zh-CN.md#当前使用限制)。

所有主机上的 ring 记录、原始归档、构建元数据和输出 pcapng 均显式使用小端编码。
内核读取、map 配置、过滤条件和统计计数使用本机字节序，USB payload 和 setup 字节保持原样。
元数据在发布前于 ring 内存中就地转换，以满足 BPF 栈大小限制。工具链要求和跨字节序回放测试
见[大端支持指南](big-endian.zh-CN.md)。

可安全提前判断的必要条件在 BPF 中执行，完整的精确匹配在重组后执行。
支持的条件及缺失数据处理规则见[过滤语法（英文）](filters.md)。

## 完成事件挂载点

仅当 `usb_unanchor_urb` 的直接调用者为 `__usb_hcd_giveback_urb` 时，程序才在该挂载点
复制 IN 数据，此时 DMA 映射已解除、数据已回拷，且驱动回调尚未执行。缺少必要挂载点或
符号地址被隐藏会导致启动失败。这一调用顺序属于内核内部行为，需要回归测试保障。

## Scatter-gather 缓冲区

bulk SG 缓冲区支持 x86_64 和 arm64 的 SPARSEMEM_VMEMMAP 内核。x86_64 读取
`vmemmap_base` 和 `page_offset_base`；arm64 根据运行内核的配置、页大小及 CO-RE 获得的
`struct page` 大小推导映射。这是 CPU 虚拟内存地址转换，不使用 DMA 地址进行换算。
遇到不支持的内存模型、ISO SG 缓冲区或不可读内存时会明确报告，
并使 `--fail-on-loss` 检查失败。

各架构的地址映射细节和验证范围见[平台支持指南（英文）](platforms.md)。

## 实现与验证记录

[实现记录（英文）](implementation.md)保留了设计约束、已完成阶段、回归证据和待验证事项。
常规内核矩阵及本地已验证配置见 [CI 指南（英文）](ci.md)。
