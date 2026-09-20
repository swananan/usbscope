# 构建与测试指南

[README](../README.zh-CN.md) · [English](development.md) | 简体中文

请在仓库根目录执行以下命令。抓包实现和 CO-RE 链接方式见[实现说明](architecture.zh-CN.md)。

[构建与测试](#构建与测试) · [内核开发测试](#内核开发测试) ·
[交叉编译（英文）](platforms.md#build-and-package) · [内核 CI（英文）](ci.md)

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
本机构建、交叉构建和 ARM e2e 命令见[平台支持指南（英文）](platforms.md)。

## 内核开发测试

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
运行测试。[对比指南（英文）](usbmon-comparison.md)说明了同步方式、字段和载荷匹配规则，
以及如何明确处理 usbmon/libpcap 的截断行为，也记录了对比检查器的负向测试。

GitHub Actions 运行用户态检查和分层内核矩阵。PR 与 `main` 分支 push 运行 **12 项 VM 任务**：
6.6.142、6.18.52 分别搭配 x86_64、arm64/4 KiB、arm64/64 KiB，以及 USB_MON 关闭、开启两种配置。
夜间和默认的手动运行执行 **36 项任务**，额外覆盖 6.6.157、6.8、6.12.110、7.2.6。
每个 USB_MON 开启的任务都要求通过 SG/音频和连续 bulk 缓冲区两套独立 tcpdump 对比。
每种架构只构建一次发布程序和 BPF 对象，再用于所有内核。固定的 `kernel-e2e` 检查要求所选任务全部通过。

[CI 指南（英文）](ci.md)说明了版本锁定、精简内核缓存、测试产物、本地复现方法和验证记录。
托管工作流尚未运行；当前验证边界仍见[使用限制](usage.zh-CN.md#当前使用限制)。
