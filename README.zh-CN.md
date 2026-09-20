# usbscope

[English](README.md) | 简体中文

usbscope 是一个基于 eBPF 的 USB 抓包命令行工具，面向 **Linux 内核编译时未启用
`CONFIG_USB_MON` 的小众场景**。它不依赖 usbmon，提供参考 tcpdump 设计的命令参数、
面向 USB 的过滤表达式，以及可供 Wireshark 读取的抓包文件。

项目采用 **Aya 和 Rust eBPF**，通过少量 C 访问函数支持 **eBPF CO-RE
（Compile Once, Run Everywhere，编译一次，到处运行）**，使用 **BPF ring buffer**
传输抓包记录。目前已实现控制（control）、批量（bulk）、中断（interrupt）和
等时（ISO）传输抓取，包括 **Linux x86_64 和 arm64（aarch64）** 上的
bulk scatter-gather（SG，分散/聚集）缓冲区。

## 运行要求与最低内核版本

**上游内核的最低功能要求为 Linux 5.17**，因为 BPF 程序依赖
[`bpf_loop`](https://github.com/torvalds/linux/blob/v5.17/kernel/bpf/bpf_iter.c#L681)。
更早的上游内核需要回移该辅助函数。但具备这一辅助函数，并不足以证明内核与本程序兼容。

**经过验证的最低内核版本为 Linux 6.6.142。** 测试平台为
**小端 x86_64 和 arm64**，其中 arm64 覆盖 4 KiB 和 64 KiB 页。
内核矩阵和已在本地验证的具体配置见 [CI 指南（英文）](docs/ci.md)。
这些记录之外的版本仍未验证，包括从 5.17 到早期 6.6 的版本。
当前部署应以已经验证的版本为基准；实时抓包还需满足以下要求：

| 要求 | 当前限制 |
| --- | --- |
| 平台 | Linux，小端 x86_64 或 arm64（aarch64）。各架构使用各自的 CLI 和 BPF 目标文件。不支持 32 位 ARM 或其他操作系统。 |
| USB 核心 | 必须编译进内核（`CONFIG_USB=y`）。当前加载器从 vmlinux BTF 解析 USB 挂载点，尚未实现从 USB 核心模块加载相应 BTF。`CONFIG_USB_MON` 可开可关。 |
| 内核 BTF | `/sys/kernel/btf/vmlinux` 必须可读，并包含 USB 挂载点的类型和函数信息（`CONFIG_DEBUG_INFO_BTF`）。 |
| BPF 与跟踪功能 | 需要 BPF 系统调用/JIT、ringbuf、`bpf_loop`、fentry/fexit 和 kprobes。已测试的配置见 [VM 内核构建脚本](tests/vm/build-kernel.sh)。 |
| 内核符号 | 必须能够从 `/proc/kallsyms` 读取所需函数的非零地址。符号地址被隐藏时无法启动。 |
| 权限 | 实时抓包已在 root 权限下测试。内核安全策略必须允许 BPF 跟踪及内核符号访问；受限容器或内核 lockdown 可能阻止抓包。 |
| arm64 SG 配置 | 需要可读且与运行内核一致的 `/proc/config.gz` 或 `/boot/config-$(uname -r)`。SG 地址转换使用页大小和 `CONFIG_ARM64_VA_BITS`；配置缺失或不受支持时禁用 SG 抓取，受影响的事件会被报告为丢失。 |

使用 `-r` 离线读取文件不会加载 BPF 程序，因此不需要上述实时抓包权限、内核 BTF、
USB 硬件或 BPF 目标文件。

## eBPF CO-RE 支持

Clang 根据 C 访问函数生成针对内核字段偏移和类型大小的 BTF CO-RE 重定位信息，
`bpf-linker` 将其链接进 Rust BPF 目标文件，Aya 则在加载时根据运行中内核的 BTF
完成重定位。**各受支持架构均使用同一个 BPF 目标文件，通过 Linux 6.6.142、6.8、
6.12.110、6.18.52 和 7.2.6 的 e2e 测试**；具体配置见 [CI 指南（英文）](docs/ci.md)。
对于目标架构上兼容的内核，无需针对每种内核结构布局重新编译。抓包主机不需要内核头文件、
Clang 或 libbpf。不同 CPU 架构的探针寄存器约定不同，因此需要各自的 BPF 目标文件；
CLI 会在加载前拒绝架构或配置 ABI 不匹配的文件。

CO-RE 处理的是结构体布局变化。所需的 BPF 辅助函数、可挂载的 USB 函数及其执行顺序仍须满足要求。
完成事件的挂载点依赖内核内部行为，因此其他内核版本或配置仍需通过回归测试后才能确认兼容性。

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

具体证据见[实现与验证说明（英文）](docs/implementation.md)；支持的过滤字段和缺失数据处理规则
见[过滤语法（英文）](docs/filters.md)。

## 抓包语义

观测单位是 USB Request Block（URB）的提交、完成或提交错误事件。这是主机侧软件跟踪，
并非电气层总线跟踪。程序不人为设置载荷截断长度：传输记录会分块发送，再在用户态重组。
资源耗尽和缓冲区不可读会明确报告为抓取丢失，不会将不完整数据伪装为完整数据。

标准输出文件采用 pcapng 格式，链路类型为 `LINKTYPE_USB_LINUX_MMAPPED`（220），
包含 ISO 描述符及其原始偏移。Wireshark 有自己的单条记录长度限制（目前 USB 为 128 MiB）；
分块原始归档保留原始传输事件，不受该读取器限制的约束。

## 构建与测试

用户态 Rust 固定为 1.98.1。BPF 构建使用 Rust `nightly-2025-12-01`、
`bpf-linker 0.9.15` 和 Clang 18。先通过系统包管理器安装 Clang 18 和 TShark，
再构建用户态和 BPF 两部分：

```sh
rustup toolchain install nightly-2025-12-01 --component rust-src
cargo +nightly-2025-12-01 install bpf-linker --version 0.9.15 --locked
cargo build --release --locked
scripts/build-ebpf.sh
cargo test --workspace --locked
python3 tests/e2e.py --binary target/release/usbscope --require-tshark
```

CLI e2e 测试独立生成传输归档，调用命令行程序，并通过 TShark 核对 USB 字段和载荷字节。
测试需要 Python 3；指定 `--require-tshark` 后，缺少外部解码器会导致测试失败，而不是跳过验证。

`scripts/package.sh` 在 `target/dist/` 中生成本机架构的 x86_64 或 aarch64 Linux 发布归档，包含 CLI、
BPF 目标文件、文档、许可证，以及二进制和 BPF 目标文件的 SHA-256 校验值。
解压后请将 `usbscope` 和 `usbscope.bpf.o` 放在同一目录。CLI 会自动查找同目录下的
BPF 目标文件，不受当前工作目录影响。产物面向 Linux GNU，libc 要求取决于所选编译器和 sysroot。
在 x86_64 Linux 构建主机上，安装 `gcc-aarch64-linux-gnu` 后可交叉构建：

```sh
rustup target add aarch64-unknown-linux-gnu
scripts/package.sh aarch64
```

产物为 `target/dist/usbscope-aarch64-linux.tar.gz`。仅构建 ARM BPF 部分时可运行
`scripts/build-ebpf.sh aarch64`，输出为 `target/aarch64/usbscope.bpf.o`。
本机构建、交叉构建和 ARM e2e 命令见[平台支持指南（英文）](docs/platforms.md)。

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

## 实时抓包

```sh
target/release/usbscope -D
sudo target/release/usbscope -i usb2 --device 2 -w capture.pcapng
sudo target/release/usbscope -i any --duration 30 --raw-output capture.usbraw -w capture.pcapng --fail-on-loss
```

未指定 `-w` 时，CLI 打印事件摘要。`-c` 按完整事件计数；`-B` 设置 ring 容量，单位为 KiB，
并非报文长度。程序优先查找可执行文件同目录下的 BPF 目标文件，随后尝试
`target/usbscope.bpf.o`；也可通过 `--bpf-object` 指定路径。

仅当 `usb_unanchor_urb` 的直接调用者为 `__usb_hcd_giveback_urb` 时，程序才在该挂载点
复制 IN 数据，此时 DMA 映射已解除、数据已回拷，且驱动回调尚未执行。缺少必要挂载点或
符号地址被隐藏会导致启动失败。这一调用顺序属于内核内部行为，需要回归测试保障。
停止抓包时，程序停止跟踪新的 URB 提交，并留出 200 ms 接收完成事件。
届时仍未完成的 URB 会单独报告，与传输记录丢失区分统计。

bulk SG 缓冲区支持 x86_64 和 arm64 的 SPARSEMEM_VMEMMAP 内核。x86_64 读取
`vmemmap_base` 和 `page_offset_base`；arm64 根据运行内核的配置、页大小及 CO-RE 获得的
`struct page` 大小推导映射。这是 CPU 虚拟内存地址转换，不使用 DMA 地址进行换算。
遇到不支持的内存模型、ISO SG 缓冲区或不可读内存时会明确报告，
并使 `--fail-on-loss` 检查失败。

## 过滤器

```sh
sudo target/release/usbscope -w capture.pcapng 'vid 0x1234 and bulk and in'
target/release/usbscope -r capture.usbraw -w slow.pcapng 'event complete and latency > 2ms'
target/release/usbscope -d 'bus 1 or payload contains 0x55534243'
```

[USB 过滤语法（英文）](docs/filters.md)支持布尔组合、数值比较、掩码、控制传输 setup 字段、
流式载荷搜索和延迟过滤。可安全提前判断的必要条件在 BPF 中执行，完整的精确匹配在重组后执行。
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

## 内核开发测试

C CO-RE shim 编译为 LLVM bitcode，再与 Rust 程序链接；抓包时不需要 C 编译器或 libbpf。
Rust 负责探针、抓包策略、BPF map 和 ring 传输，C 负责访问内核结构体。
可通过 `BPF_TOOLCHAIN`、`BPF_LINKER` 和 `BPF_CLANG` 覆盖构建工具设置。

```sh
sh scripts/build-ebpf.sh
sh tests/vm/build-kernel.sh /path/to/linux-source
python3 tests/vm/run.py
python3 tests/vm/run.py --live
python3 tests/vm/run.py --live --audio
python3 tests/vm/run.py --live --audio --filters
python3 tests/vm/run.py --live --audio --filters --sg --release
```

VM 测试运行器需要对应来宾架构的 QEMU、BusyBox 和用户态库，以及 GCC、cpio 和 Linux 源码树。
它支持本机和跨架构测试，使用 TCG，因此不需要宿主机 root 权限或 KVM。来宾系统会确认 usbmon 已禁用，
挂载真实探针，触发 USB 描述符请求，并将抓取的元数据与独立 usbfs 操作的结果比较。
即使挂载成功，若没有捕获到匹配事件，测试仍会失败。日志保存在 `target/vm-e2e.log`。

实时抓包测试还覆盖 2 MiB + 512 字节的 USB 存储读写、唯一的 URB 配对、逐字节载荷比较、
字节完全一致的归档回放、TShark 解码，以及刻意缩小 ring 后必须报告丢失并使严格模式失败的场景。
测试还会确认不匹配的 BPF 文件被拒绝，并核对来宾与宿主机的回放和过滤结果，包括两者架构不同时。
产物保存在 `target/vm-artifacts`。音频测试会针对所选内核构建仅用于 VM 的测试驱动，
将含 137 帧的稀疏 ISO 传输与驱动独立记录的结果进行核对。

要进行独立的实时抓包对比，可额外构建启用 usbmon 的内核，并使用 `--compare-tcpdump`
运行测试。[对比指南（英文）](docs/usbmon-comparison.md)说明了同步方式、字段和载荷匹配规则，
以及如何明确处理 usbmon/libpcap 的截断行为，也记录了对比检查器的负向测试。

GitHub Actions 运行用户态检查和分层内核矩阵。PR 与 `main` 分支 push 运行 **12 项 VM 任务**：
6.6.142、6.18.52 分别搭配 x86_64、arm64/4 KiB、arm64/64 KiB，以及 USB_MON 关闭、开启两种配置。
夜间和默认的手动运行执行 **36 项任务**，额外覆盖 6.6.157、6.8、6.12.110、7.2.6。
每个 USB_MON 开启的任务都要求通过 SG/音频和连续 bulk 缓冲区两套独立 tcpdump 对比。
每种架构只构建一次发布程序和 BPF 对象，再用于所有内核。固定的 `kernel-e2e` 检查要求所选任务全部通过。

[CI 指南（英文）](docs/ci.md)说明了版本锁定、精简内核缓存、测试产物、本地复现方法和验证记录。
托管工作流尚未运行；当前验证边界仍见[使用限制](#当前使用限制)。

## 许可证

除文件另有声明外，usbscope 的源代码和文档采用 [MIT 许可证](LICENSE-MIT) 或
[Apache License 2.0](LICENSE-APACHE)，可任选其一（`MIT OR Apache-2.0`）。

eBPF 目标文件保留 `Dual MIT/GPL` 许可声明，以满足
[Linux 内核对 BPF 程序的 GPL 兼容性检查要求](https://docs.kernel.org/bpf/bpf_licensing.html)。
仅用于 VM 测试的 ISO 驱动单独采用 [GPL-2.0](tests/vm/kernel/COPYING)。
第三方依赖保留各自的许可证。
