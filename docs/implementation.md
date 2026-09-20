# Implementation and validation

Each completed stage is committed separately. A stage is not complete merely
because it compiles. Hardware/VM coverage and known limitations are recorded here.

| Stage | Scope | Status |
| --- | --- | --- |
| P0.1 | Workspace, versioned ring ABI, reassembly, pcapng, CLI e2e | Complete |
| P0.2 | Rust/C CO-RE build and VM eBPF smoke test | Pending |
| P1 | Live S/C/E capture, long payload, filtering, loss accounting | Pending |
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
