# Implementation and validation

Each completed stage is committed separately. A stage is not complete merely
because it compiles. Hardware/VM coverage and known limitations are recorded here.

| Stage | Scope | Status |
| --- | --- | --- |
| P0.1 | Workspace, versioned ring ABI, reassembly, pcapng, CLI e2e | Complete |
| P0.2 | Rust/C CO-RE build and VM eBPF smoke test | Complete |
| P1 | Live S/C/E hooks, contiguous long payload, bus/device selection, loss accounting | Complete |
| P2 | ISO/audio metadata and sparse payload, device context | Pending |
| P3 | Complete filter language, offline analysis, rotation and release checks | Pending |

## Invariants

- No payload or ISO descriptor-count snap limit.
- Copy OUT data at submission and IN data only after DMA synchronization and
  bounce-buffer copyback, before the driver callback can reuse the URB.
- Each submission gets a new ID; pointers are never used as persistent capture IDs.
- All kernel memory reads finish inside the observing probe invocation.
- A complete event must include every required descriptor and payload range.
- Ring failures have independent map counters; reporting a loss cannot rely on
  successfully writing another record to the same full ring.
- CO-RE must be checked using different kernel layouts, not just the presence of BTF.
- The kernel e2e target must actually have `CONFIG_USB_MON=n`.

## Test layers

1. CLI archive-to-pcapng e2e: independent fixture producer and TShark decoder.
2. QEMU kernel e2e: actual USB I/O through probes and ringbuf, with no usbmon.
3. Cross-kernel/architecture and USB-controller coverage, including DMA copyback.

The first layer does not establish that a kernel probe works. VM tests must
record visible capture side effects, not just a successful load or attach.

## P0.1 validation

Nine CLI e2e tests pass with TShark 4.4.8. They cover a 2 MiB + 4 byte payload,
interleaved/reversed fragments, 137 sparse ISO descriptors, control setup,
binary stdout, missing records, explicit kernel errors, overlapping fragments,
and malformed archive lengths. `cargo clippy --workspace --all-targets -- -D warnings`
and formatting checks pass. These are userspace pipeline tests, not live capture tests.

## P0.2 validation

The same BPF ELF, built with Rust nightly-2025-12-01, bpf-linker 0.9.15, and
Clang 18, passed the rootless QEMU smoke test on Linux 6.6.142 and 6.8.
Both kernels have `CONFIG_USB_MON=n`. The C type views deliberately omit and
reorder kernel fields, so matching bus/device/VID/PID/setup data requires actual
CO-RE relocation. The independent USBDEVFS_CONTROL request and captured metadata
matched. This establishes submission metadata and ring transport; full payload,
completion ordering, SG, and audio remain later-stage validation requirements.

Linux 6.6's BPF JIT depends on `CONFIG_MODULES`, even when all test drivers are
built in. The kernel builder checks the resolved config before building.

## P1 validation

The same BPF object passed full live CLI e2e on Linux 6.6.142 and 6.8 with
`CONFIG_USB_MON=n`. Each run captured nine S/C pairs, including control IN and
single-URB bulk transfers of 2,097,664 bytes in each direction. Payloads matched
usbfs data byte for byte, URB IDs were unique, completion status was zero, raw
replay was byte-identical, and TShark parsed all 18 events. A 4 KiB ring forced
capture loss; map counters increased and strict mode exited unsuccessfully.

The test exposed LLVM 21's relaxed atomic-add lowering without `BPF_FETCH`.
ID allocation uses SeqCst and BPF v3; the e2e asserts uniqueness and pairing.
Rust intrinsics are needed because the BPF core target does not expose standard
atomic read-modify-write methods. C remains limited to CO-RE structure reads.

Submission failures have a loaded fexit hook, but this suite has not yet forced
an HCD enqueue failure. ISO, SG, real hardware DMA bounce paths, and aarch64 are
not covered by this stage. The post-DMA completion hook uses the immediate
caller address, rejecting unrelated and concurrent `usb_unanchor_urb` calls.
