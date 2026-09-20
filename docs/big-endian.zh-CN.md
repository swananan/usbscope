# ARM 大端支持

[README](../README.zh-CN.md) · [English](big-endian.md) | 简体中文

大端支持的目标是 Linux **arm64**，构建和 VM 命令中称为 `aarch64_be`；构建与打包脚本
也接受 `arm64_be`。目前不包含 s390x、PowerPC 或 32 位 ARM。实时抓包需要匹配的大端
CLI 和 `bpfeb` 对象；arm64 小端继续使用 `aarch64` 与 `bpfel`。

## 内核范围

矩阵为 **6.6.142、6.6.157、6.8、6.12.110** 配置大端测试，覆盖 4 KiB/64 KiB 页和
USB_MON 开关两种状态。[CI 验证记录（英文）](ci.md#validation-status)区分本地已验证配置
与托管矩阵范围。BTF、USB 挂载点、VA48 和 SPARSEMEM_VMEMMAP 等现有要求仍然适用。

锁定的 **6.18.52 和 7.2.6** 源码将 `CPU_BIG_ENDIAN` 设为依赖 `BROKEN`，因此这些版本
只运行小端测试。构建器不会覆盖 `BROKEN` 或修改内核来启用大端。参见上游
[arm64 Kconfig](https://github.com/torvalds/linux/blob/v6.18/arch/arm64/Kconfig)及
[内核清单](../scripts/ci/kernels.json)中的显式能力标记。

## 在 x86_64 Linux 上构建

先安装 [BPF 工具链](development.zh-CN.md#构建与测试)，以及 `build-essential`、`flex`、
`bison`、`pkg-config`、`file`、`qemu-user`、`qemu-system-arm`、`cpio` 和 TShark。
准备脚本下载 SHA-256 锁定的源码与独立 Bootlin SDK，不向宿主系统安装外架构软件包，
也不需要 root。

```sh
rustup toolchain install nightly-2026-09-18 --component rust-src
python3 tests/vm/prepare-big-endian.py
. target/be-tools/environment.sh
scripts/package.sh aarch64_be
scripts/build-userspace.sh aarch64_be --release --example probe-smoke
scripts/ci/test-big-endian.sh
```

产物为 `target/dist/usbscope-aarch64_be-linux.tar.gz`，安装时保持 CLI 与 BPF 对象同目录。
BPF 工具链仍为 `nightly-2025-12-01`、Clang 18 和 `bpf-linker 0.9.15`。
大端用户态单独固定为 `nightly-2026-09-18`，使用 `-Z build-std` 构建标准库，因为 Rust
不为该目标提供预编译标准库。本地测试发现旧 nightly 的 ARM 大端 NEON 字符串查找会
导致 ELF 解析错误。可通过 `BE_TOOLCHAIN` 更换用户态版本，但需重新通过同一套 e2e。

SDK 固定为 Bootlin `aarch64be--glibc--stable-2025.08-1`（GCC 14.3、glibc 2.41）。
CLI 与来宾可执行文件均采用静态链接及 64 KiB 段对齐，兼容两种已测试页大小；SDK 自带的
动态加载器只能用于 4 KiB 页。Rustix 在该目标上使用 libc 后端。内核 gzip 配置读取使用
flate2 的 zlib-rs 后端，避开 crc32fast ARM CRC 路径的本机字序假设；独立的 Python gzip
样本同时验证正确解压和损坏校验和拒绝。

来宾工具为 BusyBox 1.37.0、libpcap 1.10.4、tcpdump 4.99.5。libpcap 与小端基准保持
一致：测试发现 1.10.5 在 ISO 提交报文的原始长度中遗漏描述符，产生 `caplen > len`。
比较器保留严格的报文长度检查。下载地址及校验值见
[准备脚本](../tests/vm/prepare-big-endian.py)。

## 常规 e2e 与本地复现

构建任务通过 `qemu-aarch64_be` 运行单元测试及全部 23 项 CLI/TShark e2e。
内核任务启动真实的大端内核，并同时检查进程字节序与 `CONFIG_CPU_BIG_ENDIAN=y`。
使用现有 USB 流量生成器，覆盖每方向 2,097,664 字节的完整载荷、SG、137 帧稀疏 ISO、
过滤、强制丢失及错误对象拒绝。USB_MON 开启时，还必须通过 SG/音频与连续缓冲区两套
tcpdump 对比和损坏抓包的负向检查。

按 [CI 指南（英文）](ci.md#local-reproduction-and-updates)准备内核构建依赖后，可复现
CI 使用的发布包路径：

```sh
env -u CROSS_COMPILE scripts/ci/build-userspace.sh x86_64
scripts/ci/build-userspace.sh aarch64_be
. target/be-tools/environment.sh
JOBS=4 python3 scripts/ci/kernel.py build --version 6.12.110 \
  --arch aarch64_be --pages 64K --usbmon y
scripts/ci/run-vm.sh aarch64_be 6.12.110 64K y
```

不同内核配置应使用各自的构建目录和 bundle。同一大端 BPF 对象复用于不同内核和页大小。

## 文件兼容性

所有主机上的 ring 记录、`.usbraw` 归档、构建元数据及输出 pcapng 都采用显式小端编码，
USB payload/setup 字节保持原样。map 值与内核结构读取使用本机字节序。原始归档 ABI
仍为版本 1，现有小端读取器可读取大端主机抓出的文件。VM 测试在大端来宾和小端宿主上
分别回放归档，逐字节比较 pcapng 及过滤结果。独立 tcpdump 比较器也支持大端 pcap 文件头
和 USB 伪头。
