# Implementation and validation

Each completed stage is committed separately. A stage is not complete merely
because it compiles. Hardware/VM coverage and known limitations are recorded here.

| Stage | Scope | Status |
| --- | --- | --- |
| P0.1 | Workspace, versioned ring ABI, reassembly, pcapng, CLI e2e | Complete |
| P0.2 | Rust/C CO-RE build and VM eBPF smoke test | Complete |
| P1 | Live S/C/E hooks, contiguous long payload, bus/device selection, loss accounting | Complete |
| P2 | ISO/audio metadata, sparse payload, ISO statistics, initial device context | Complete |
| P3.1 | USB filter language, safe kernel prefilter, archive analysis | Complete |
| P3.2 | x86_64 SG buffers and randomized-layout VM coverage | Complete |
| P3.3 | pcapng input, rotation and release checks | Complete |

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

## P2 validation

Live audio e2e passed on Linux 6.6.142 and 6.8 using QEMU's USB audio device.
A VM-only test driver submits one 137-frame ISO URB (usbfs itself caps these at
128). Frames have distinct byte patterns, variable lengths, and 32+ byte gaps.
All submission bytes and original offsets match; gaps contain zeroes, not the
fixture's sentinel bytes. Completion lengths/status match independently exported
driver results, including 46 zero-length completions. TShark sees all 137
descriptors. Both full suites still pass the long bulk and ring-loss tests.

`--iso-stats` reports completion/frame errors, bytes, empty frames, and observed
URB completion gaps. `--device-context` saves a passive initial sysfs snapshot
including raw descriptor bytes. It is not a hotplug/alternate-setting timeline
and does not inject fabricated enumeration packets into Wireshark. Live ISO IN,
UAC2/UAC3 feedback decoding, PCM/WAV reconstruction, and hardware timing remain
unvalidated or unimplemented; synthetic sparse ISO IN coverage is separate.

## P3.1 validation

Fifteen CLI/TShark e2e tests cover boolean precedence, masks, setup fields,
unknown fields under negation, payload patterns crossing transport chunks,
big endian slices, latency using an otherwise filtered submission, and exclusion
of ISO padding from byte searches. A compiler soundness test checks that safe
kernel predicates do not reject matching completion events across combinations
of metadata, errors, and payload bytes.

Live filter e2e passed on both kernels: a bulk/length/complete/latency expression
allowed exactly two large URBs into the kernel stream and selected their two
completions. `bus 999 or payload contains 0x55534243` retained all nine input
URBs and selected the three matching command submissions without false negatives.
The full audio, payload, replay, TShark, and loss suites remain enabled.

## P3.2 validation

Both VM kernels now enable relocatable/randomized memory layouts and boot without
`nokaslr`. Asynchronous usbfs transfers exercise SG lists rather than contiguous
buffers. The full suites pass on both kernels, including byte-exact 2,097,664
byte transfers in each direction; kernel counters assert two SG data events.
The C shim uses runtime `vmemmap_base` and `page_offset_base` values, CO-RE sizes
for `struct page` and `struct scatterlist`, and follows SG chain links. Copying
uses one bounded helper loop sized from the actual payload and SG entry count.

Supported SG translation is x86_64 SPARSEMEM_VMEMMAP with 4 KiB base pages and
visible layout symbols. Other memory models, ISO SG buffers, device-only DMA
memory, and inaccessible pages fail explicitly as unsupported/read loss. The
suite exercises 129 contiguous SG entries; separately allocated chained SG tables
are implemented but not yet exercised by this fixture.

## P3.3 validation

Twenty-three CLI/TShark e2e tests pass against the optimized release binary built
with pinned Rust 1.98.1. New cases cover pcapng round trips, big-endian sections,
nanosecond resolution and timestamp offsets, missing identity metadata, truncated
packets, malformed block lengths, and unsupported packet block types. Input is
streamed through spooled temporary files; it does not allocate a payload-sized
buffer. Only LINKTYPE_USB_LINUX_MMAPPED Enhanced Packet Blocks are supported.

Rotation tests exercise size/time boundaries, a complete event larger than the
rotation target, file-count stopping, and refusal to overwrite existing rotated
files. Additional checks protect input hard links, BPF objects, and raw archive
paths from output aliasing. An intentional offline event/file limit discards
pending fragments without misreporting them as transport loss.

Orderly live shutdown appends independent kernel counter totals to the raw
archive. A counter-only fixture and the actual VM ring-exhaustion test verify
that replay still fails strict mode when an entire event disappears from the
ring. A killed process can lack this final summary; pcapng output itself does
not preserve the raw archive's counter summary.

The full release suites pass on both Linux 6.6.142 and 6.8 with USB_MON disabled
and randomized layouts: 24 events (12 S/C pairs), byte-exact large SG transfers,
137 sparse ISO frames, filters, TShark decoding, archive replay, and forced loss.
Normal runs have no ring, read, unsupported-buffer, or state errors. The same
BPF object is used on both kernels. A fresh install of bpf-linker 0.9.15 built
with the pinned nightly produced the tested object.

Formatting, Clippy with warnings denied, and the filter compiler soundness test
pass. The repository includes userspace CI, a two-kernel VM workflow, and a
package script producing the native x86_64 CLI, adjacent BPF object, documentation,
licenses, and checksums. The hosted workflows have not yet run; the corresponding
release validation commands have run locally.

## Remaining validation and scope

- Physical controllers and DMA bounce/copyback paths need hardware testing.
- Live ISO IN, interrupt traffic, separately allocated SG chains, and HCD enqueue
  failure paths need dedicated kernel fixtures; existing coverage must not be
  treated as evidence for those cases.
- aarch64 and other memory models are not validated. SG address translation
  currently supports x86_64 SPARSEMEM_VMEMMAP with 4 KiB pages only.
- Post-DMA observation uses kernel-internal hook ordering and readable symbol
  addresses. Other kernel versions/configurations require regression testing.
- Device context is an initial snapshot. Hotplug/alternate-setting timelines,
  UAC feedback decoding, and PCM/WAV export are future work.
- Full-length capture does not guarantee lossless capture at every data rate.
  Ring capacity, disk space, temporary storage, and capture-format/reader limits
  remain resource constraints; errors and incomplete events are reported.
