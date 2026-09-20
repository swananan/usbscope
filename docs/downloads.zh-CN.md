# 下载与运行依赖

[README](../README.zh-CN.md) · [English](downloads.md) | 简体中文

## 下载构建产物

打开 [build 工作流](https://github.com/swananan/usbscope/actions/workflows/build.yml)，
选择所需提交对应的成功运行，在 **Artifacts** 中下载目标平台的产物。
每个产物包含一个 `.tar.gz` 归档及其 `.sha256` 校验文件。

| Linux 目标平台 | Artifact / 归档名称前缀 |
| --- | --- |
| x86_64，小端 | `usbscope-x86_64-linux` |
| arm64，小端 | `usbscope-aarch64-linux` |
| arm64，大端 | `usbscope-aarch64_be-linux` |

解开下载的 Artifact ZIP 后，验证并解压其中的归档。以 x86_64 为例：

```sh
sha256sum --check usbscope-x86_64-linux.tar.gz.sha256
tar -xzf usbscope-x86_64-linux.tar.gz
cd usbscope-x86_64-linux
sha256sum --check SHA256SUMS
./usbscope --help
sudo ./usbscope -i any --duration 30 -w capture.pcapng --fail-on-loss
```

请将 `usbscope` 和 `usbscope.bpf.o` 保持在同一目录。归档还包含文档与许可证。
ARM 可执行文件采用 64 KiB 段对齐，覆盖两种已支持页大小。归档内 CLI 去除了调试信息，
本地原始构建文件仍保留调试信息；BPF 对象的 BTF 和 CO-RE 重定位数据完整保留。

## 抓包机器需要什么

三个平台的发行版 CLI 都是**静态链接**，包括 C 运行库，没有 ELF 动态加载器或
`DT_NEEDED` 共享库依赖。目标机器无需安装 Rust、Clang、LLVM、bpf-linker、libbpf、
libpcap 或匹配版本的动态 libc。Wireshark/TShark 仅用于查看输出文件，usbscope 本身不调用它们。

实时抓包需要同目录的 BPF 对象，以及宿主机的内核 BTF、跟踪支持、内核配置和相应权限，
具体见[运行要求](usage.zh-CN.md#运行要求与最低内核版本)。离线读取只需要可执行文件和输入文件。

## Build CI

独立的 [build 工作流](../.github/workflows/build.yml) 在 `main` push、`v*` 标签、PR 和
手动触发时运行，三个并行任务生成上述归档，产物保留 30 天。最终的 `build` 检查要求
所有平台通过。工作流上传 Actions 产物，不自动创建或发布 GitHub Release。

每个任务检查 CLI 架构、字节序、无动态加载器/共享库依赖及 ARM 页对齐，同时验证 BPF
架构、字节序、BTF、CO-RE 重定位、校验和及可执行权限。随后将实际归档解压到新目录，
执行全部 23 项 CLI/TShark e2e。ARM 二进制通过 qemu-user 在空目标 sysroot 下执行。

Build CI 只构建 CLI 与 BPF 对象，不构建内核、BusyBox、libpcap、tcpdump 或 VM 测试组件。
QEMU 和 TShark 只在 CI 上用于验证。真实 USB 抓包继续由独立的[内核矩阵（英文）](ci.md)
覆盖，两类工作流共用同一个打包脚本。

本地构建方法见[构建指南](development.zh-CN.md)及[大端工具链说明](big-endian.zh-CN.md)。
打包机器除固定的 Rust/BPF 工具链外，还需要 Python 3，以及目标平台的 GCC/binutils 和
libc 开发文件。构建脚本使用 Rust 的
[`crt-static` 特性](https://doc.rust-lang.org/reference/linkage.html#static-and-dynamic-c-runtimes)，
并检查实际生成的 ELF。`scripts/ci/test-package.sh <arch>` 可复现归档校验和 CLI e2e，
该测试需要 TShark，ARM 测试还需要 qemu-user。
