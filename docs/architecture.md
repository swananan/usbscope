# Architecture and eBPF CO-RE

[README](../README.md) · English | [简体中文](architecture.zh-CN.md)

This guide describes how capture works. For commands and operational limits, see the
[usage guide](usage.md); for build tools and regression tests, see the
[development guide](development.md).

## Implementation overview

Built with **Aya and Rust eBPF**, it supports **eBPF CO-RE (Compile Once, Run
Everywhere)** through small C accessors and transports capture records through
a **BPF ring buffer**. Control, bulk, interrupt, and ISO capture is implemented,
including bulk scatter-gather buffers on **Linux x86_64 and arm64 (aarch64)**.

The C CO-RE shim compiles to LLVM bitcode and is linked with the Rust program;
no C compiler or libbpf is needed at capture time. Rust handles the probes,
capture policy, maps, and ring transport; C provides kernel structure access.

## eBPF CO-RE support

Clang emits BTF CO-RE relocations for kernel field offsets and type sizes from
the C accessors. `bpf-linker` links them into the Rust BPF object, and Aya applies
the relocations using the running kernel's BTF at load time. For each supported
architecture, the **same BPF object has passed e2e tests on Linux 6.6.142, 6.8,
6.12.110, 6.18.52, and 7.2.6**; the [CI guide](ci.md) records the tested configurations.
On compatible kernels of the target architecture, this avoids recompiling for
each kernel layout. Capture hosts do not need kernel headers, Clang, or libbpf.
Objects are specific to the CPU architecture because probe register conventions
differ; the CLI rejects an object built for the wrong architecture or
configuration ABI before loading it.

CO-RE handles structure layout changes. The required BPF helpers, attachable USB
functions, and their execution order must still be present. The completion hook
depends on kernel-internal behavior, so additional kernel versions/configurations
need regression testing before compatibility can be claimed.

## Event transport and filtering

Payloads and ISO metadata travel in chunks through the BPF ring buffer and are
reassembled in userspace. Payload length and ISO descriptor count have no
application-imposed snap limit. The [capture semantics](usage.md#capture-semantics)
and [usage limits](usage.md#current-usage-limits) describe completeness and format limits.

Safe necessary predicates run in BPF; exact matching runs after reassembly.
See the [filter grammar](filters.md) for supported predicates and missing-data rules.

## Completion hooks

IN data is copied at `usb_unanchor_urb` only when its immediate caller is
`__usb_hcd_giveback_urb`, after DMA unmapping/copyback and before the driver
callback. A missing required hook or redacted symbol addresses is a startup
error. This hook ordering is kernel-internal and requires regression coverage.

## Scatter-gather buffers

Bulk SG buffers are supported on x86_64 and arm64 SPARSEMEM_VMEMMAP kernels.
x86_64 reads `vmemmap_base` and `page_offset_base`; arm64 derives the mapping from
the running kernel configuration, page size, and CO-RE `struct page` size.
This translates CPU virtual memory rather than DMA addresses.
Unsupported memory models, ISO SG buffers, or unreadable memory are reported
explicitly and make `--fail-on-loss` fail.

The [platform guide](platforms.md) records architecture-specific mapping details
and validation coverage.

## Implementation and validation record

The [implementation record](implementation.md) tracks invariants, completed stages,
regression evidence, and remaining validation work. The [CI guide](ci.md) lists the
regular kernel matrix and the configurations tested locally.
