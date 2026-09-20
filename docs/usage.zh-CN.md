# 使用指南

[README](../README.zh-CN.md) · [English](usage.md) | 简体中文

先按[构建指南](development.zh-CN.md#构建与测试)准备 CLI 和 BPF 目标文件。
以下示例在仓库根目录执行，或使用 `PATH` 中的 `usbscope`。

[运行要求](#运行要求与最低内核版本) · [使用限制](#当前使用限制) · [抓包语义](#抓包语义) ·
[实时抓包](#实时抓包) · [离线读取与轮转](#离线读取与文件轮转) · [过滤器](#过滤器) · [ISO 与音频](#iso-与音频)

## 运行要求与最低内核版本

**上游内核的最低功能要求为 Linux 5.17**，因为 BPF 程序依赖
[`bpf_loop`](https://github.com/torvalds/linux/blob/v5.17/kernel/bpf/bpf_iter.c#L681)。
更早的上游内核需要回移该辅助函数。但具备这一辅助函数，并不足以证明内核与本程序兼容。

**经过验证的最低内核版本为 Linux 6.6.142。** 测试平台为
**小端 x86_64 和 arm64**，其中 arm64 覆盖 4 KiB 和 64 KiB 页。
内核矩阵和已在本地验证的具体配置见 [CI 指南（英文）](ci.md)。
这些记录之外的版本仍未验证，包括从 5.17 到早期 6.6 的版本。
当前部署应以已经验证的版本为基准；实时抓包还需满足以下要求：

| 要求 | 当前限制 |
| --- | --- |
| 平台 | Linux，小端 x86_64 或 arm64（aarch64）。各架构使用各自的 CLI 和 BPF 目标文件。不支持 32 位 ARM 或其他操作系统。 |
| USB 核心 | 必须编译进内核（`CONFIG_USB=y`）。当前加载器从 vmlinux BTF 解析 USB 挂载点，尚未实现从 USB 核心模块加载相应 BTF。`CONFIG_USB_MON` 可开可关。 |
| 内核 BTF | `/sys/kernel/btf/vmlinux` 必须可读，并包含 USB 挂载点的类型和函数信息（`CONFIG_DEBUG_INFO_BTF`）。 |
| BPF 与跟踪功能 | 需要 BPF 系统调用/JIT、ringbuf、`bpf_loop`、fentry/fexit 和 kprobes。已测试的配置见 [VM 内核构建脚本](../tests/vm/build-kernel.sh)。 |
| 内核符号 | 必须能够从 `/proc/kallsyms` 读取所需函数的非零地址。符号地址被隐藏时无法启动。 |
| 权限 | 实时抓包已在 root 权限下测试。内核安全策略必须允许 BPF 跟踪及内核符号访问；受限容器或内核 lockdown 可能阻止抓包。 |
| arm64 SG 配置 | 需要可读且与运行内核一致的 `/proc/config.gz` 或 `/boot/config-$(uname -r)`。SG 地址转换使用页大小和 `CONFIG_ARM64_VA_BITS`；配置缺失或不受支持时禁用 SG 抓取，受影响的事件会被报告为丢失。 |

使用 `-r` 离线读取文件不会加载 BPF 程序，因此不需要上述实时抓包权限、内核 BTF、
USB 硬件或 BPF 目标文件。

## 当前使用限制

- **观测层级：** 记录主机侧 URB 的提交、完成和提交错误事件，不涵盖 USB 电气层事务、
  线缆上的精确时序或总线级重试。
- **抓取完整性：** 程序不人为设置载荷（payload）长度或 ISO 描述符数量的截断上限，
  但仍受 ring 容量、待处理事件状态、临时存储、磁盘空间以及读取器和格式限制的影响。
  读取失败和资源耗尽会被报告为抓取丢失；使用 `--fail-on-loss` 可将其视为错误。
- **SG 缓冲区：** 需要 SPARSEMEM_VMEMMAP。x86_64 使用 4 KiB 页，并要求可见
  `vmemmap_base`/`page_offset_base` 符号。arm64 已验证 4 KiB/64 KiB 页及
  `CONFIG_ARM64_VA_BITS=48`，还需要读取运行内核的配置。不支持 ISO SG 缓冲区、其他内存模型
  或 arm64 带标签的 KASAN 内存。arm64 的 16 KiB 页和其他虚拟地址位数尚未验证。
- **验证范围：** 实时 control、连续缓冲区/SG bulk 和 ISO OUT 已有 QEMU e2e 覆盖。
  实体控制器、DMA bounce 路径、实时 ISO IN、中断传输、单独分配的 SG 链、入队失败及
  arm64 实体设备仍需验证。
- **音频上下文：** 设备 JSON 仅包含初始 sysfs 快照。尚未实现配置及备用设置
  （alternate setting）的变化时间线、UAC 反馈解码和 PCM/WAV 导出。

具体证据见[实现与验证说明（英文）](implementation.md)；支持的过滤字段和缺失数据处理规则
见[过滤语法（英文）](filters.md)。

## 抓包语义

观测单位是 USB Request Block（URB）的提交、完成或提交错误事件。这是主机侧软件跟踪，
并非电气层总线跟踪。程序不人为设置载荷截断长度：传输记录会分块发送，再在用户态重组。
资源耗尽和缓冲区不可读会明确报告为抓取丢失，不会将不完整数据伪装为完整数据。

标准输出文件采用 pcapng 格式，链路类型为 `LINKTYPE_USB_LINUX_MMAPPED`（220），
包含 ISO 描述符及其原始偏移。Wireshark 有自己的单条记录长度限制（目前 USB 为 128 MiB）；
分块原始归档保留原始传输事件，不受该读取器限制的约束。

## 实时抓包

```sh
target/release/usbscope -D
sudo target/release/usbscope -i usb2 --device 2 -w capture.pcapng
sudo target/release/usbscope -i any --duration 30 --raw-output capture.usbraw -w capture.pcapng --fail-on-loss
```

未指定 `-w` 时，CLI 打印事件摘要。`-c` 按完整事件计数；`-B` 设置 ring 容量，单位为 KiB，
并非报文长度。程序优先查找可执行文件同目录下的 BPF 目标文件，随后尝试
`target/usbscope.bpf.o`；也可通过 `--bpf-object` 指定路径。

停止抓包时，程序停止跟踪新的 URB 提交，并留出 200 ms 接收完成事件。
届时仍未完成的 URB 会单独报告，与传输记录丢失区分统计。

## 离线读取与文件轮转

```sh
usbscope -r capture.usbraw -w capture.pcapng --fail-on-loss
usbscope -r capture.pcapng -w selected.pcapng 'bulk and in'
sudo usbscope -i any -w capture.pcapng -C 100 -W 10
sudo usbscope -i usb1 -w audio.pcapng -G 60 --iso-stats
```

`-r` 可识别原始归档，以及包含 `LINKTYPE_USB_LINUX_MMAPPED`（220）类型 Enhanced Packet
Block 的 pcapng 文件。不支持传统 pcap 格式或其他数据块/链路类型。读取大载荷时，程序通过
临时存储进行流式处理。输入文件因抓包截断长度而缺失的数据会被报告为不完整数据。
标准 USB pcapng 不包含 VID/PID；完成事件的原始请求长度和延迟也需要观测到对应的提交事件
才能确定。缺失字段在过滤器中保留为未知值。

`-C` 以十进制 MB 为单位，`-G` 使用抓包时间戳。两者都在完整事件之间轮转文件，因此单个
大事件可能使文件超过目标大小。文件依次命名为 `capture.pcapng.000000`、`.000001` 等。
达到 `-W` 指定的文件数后停止写入，不覆盖此前文件；轮转目标路径已存在时会报错。
原始归档始终写入单个连续文件，不随 pcapng 输出一起轮转。

日志和统计信息写入 stderr，即使使用 `-w -` 将二进制数据写入 stdout 也是如此。
正常停止时，原始归档会保存内核丢失计数，包括第一条 ring 记录都未能送达的整个事件的丢失。
进程被突然终止时，最终计数快照可能来不及写入。

## 过滤器

```sh
sudo target/release/usbscope -w capture.pcapng 'vid 0x1234 and bulk and in'
target/release/usbscope -r capture.usbraw -w slow.pcapng 'event complete and latency > 2ms'
target/release/usbscope -d 'bus 1 or payload contains 0x55534243'
```

[USB 过滤语法（英文）](filters.md)支持布尔组合、数值比较、掩码、控制传输 setup 字段、
流式载荷搜索和延迟过滤。
`-F` 从文件读取过滤表达式。为兼容常见用法，接受 `-s 0`，其含义始终是抓取完整载荷；
其他截断长度会被拒绝。

## ISO 与音频

```sh
sudo target/release/usbscope -i usb1 -w audio.pcapng --iso-stats --device-context devices.json
```

每个 ISO 帧都会保留状态、原始偏移，以及请求长度（提交事件）或实际长度（完成事件）。
程序只复制有效帧区域，导出时将帧间空隙填零。描述符数量不限制为 128 个。
统计信息包括空帧、错误和 URB 完成间隔；这些都是软件侧观测值，并非精确的总线时序。

可选的设备 JSON 包含初始、被动采集的 sysfs 快照，其中包括描述符字节。
它不构成完整的配置或热插拔时间线，也不会自动让 Wireshark 识别此前已完成枚举的音频设备。
需要 USB 类专用解码时，应一并抓取设备枚举过程。目前尚未实现 PCM/WAV 提取和 UAC 反馈解析。
