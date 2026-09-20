# Implementation and validation

Each completed stage is committed separately. A stage is not complete merely
because it compiles. Hardware/VM coverage and known limitations are recorded here.

For the current design, see the [architecture and CO-RE guide](architecture.md).
Build commands and test setup are in the [development guide](development.md);
operational requirements and limits are in the [usage guide](usage.md).
Stage notes describe validation at the time of implementation. Later hosted
results are recorded in [P7](#p7-github-actions-validation).

| Stage | Scope | Status |
| --- | --- | --- |
| P0.1 | Workspace, versioned ring ABI, reassembly, pcapng, CLI e2e | Complete |
| P0.2 | Rust/C CO-RE build and VM eBPF smoke test | Complete |
| P1 | Live S/C/E hooks, contiguous long payload, bus/device selection, loss accounting | Complete |
| P2 | ISO/audio metadata, sparse payload, ISO statistics, initial device context | Complete |
| P3.1 | USB filter language, safe kernel prefilter, archive analysis | Complete |
| P3.2 | x86_64 SG buffers and randomized-layout VM coverage | Complete |
| P3.3 | pcapng input, rotation and release checks | Complete |
| P3.4 | Independent tcpdump capture comparison and regular VM matrix | Complete |
| P4.1 | Native/cross arm64 builds and rootless VM capture e2e | Complete |
| P4.2 | arm64 SG, 4 KiB/64 KiB pages, architecture/ABI guards | Complete |
| P4.3 | Architecture-specific releases, twelve-job CI matrix, platform documentation | Complete; later hosted validation in P7 |
| P5.1 | ARM SG compatibility with the upstream 6.9+ memory layout | Complete |
| P5.2 | Pinned PR/full kernel CI, shared build artifacts, compact verified caches | Complete; later hosted validation in P7 |
| P5.3 | Verifier compatibility on 7.2 and final cross-kernel object regression | Complete |
| P6 | arm64 big endian, cross-endian replay, three-target packages and CI | Complete |
| P7 | GitHub repository, hosted CI fixes and validation | Userspace and 16-job matrix passed; full run linked below |

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
- The ordinary kernel e2e target must actually have `CONFIG_USB_MON=n`;
  the separate differential target requires `CONFIG_USB_MON=y`.

## Test layers

1. CLI archive-to-pcapng e2e: independent fixture producer and TShark decoder.
2. QEMU kernel e2e: actual USB I/O through probes and ringbuf, with no usbmon.
3. Independent live tcpdump/usbmon comparison in an additional USB_MON-enabled VM.
4. Cross-kernel/architecture and USB-controller coverage, including DMA copyback.

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
licenses, and checksums. At this stage the hosted workflows had not yet run; the corresponding
release validation commands have run locally.

## P3.4 validation

Independent live tcpdump/usbmon comparison passed on Linux 6.6.142 and 6.8 with
`CONFIG_USB_MON=y`, using tcpdump 4.99.4 and libpcap 1.10.4. Each kernel ran two
release-build cases:

| Traffic | Matched events / URBs | Valid payload bytes compared | ISO descriptors compared |
| --- | --- | --- | --- |
| Control, SG bulk, sparse ISO OUT | 24 / 12 | 516,132 | 256 |
| Control, contiguous bulk | 18 / 9 | 491,670 | 0 |

Both collectors had zero reported drops in the compared captures. Metadata,
control setup, phase/status/length/flags, non-ISO payload prefixes, and all
reference-described ISO regions matched. TShark decoded both files. The
reference snapshot was 245,824 bytes;
each large bulk transfer retained a 245,760-byte prefix. usbmon retained 128 of
137 ISO descriptors in each event. The checker requires these exact documented
boundaries and reports them separately; independent fixtures continue to verify
the complete 2,097,664-byte payloads and all 137 usbscope ISO frames.

Ten deliberate corruptions of each audio capture and eight of each contiguous
capture were rejected, including missing whole URBs and usbscope truncation
beyond the reference's prefix. The full USB_MON-disabled Linux 6.6.142 suite was
also rerun successfully after the runner changes. No capture implementation
changes were needed to pass the differential tests.

CI now has two kernels times two USB_MON configurations. Both enabled jobs run
the SG/audio comparison and a second contiguous-buffer comparison, preserving
captures, collector versions, comparison JSON, and guest logs. These commands
have run locally; at this stage the hosted workflow had not yet run. See the
[comparison guide](usbmon-comparison.md) for reproducible commands, normalization
rules, and the scope of the baseline.

## P4 arm64 validation

Rootless QEMU TCG runs passed on arm64 Linux 6.6.142 and 6.8. Each kernel was
tested with both 4 KiB and 64 KiB pages and `CONFIG_ARM64_VA_BITS=48`. The same
arm64 BPF object was used across these configurations. The tested cases include
control, contiguous/SG bulk, 137-frame sparse ISO OUT, filters, exact full-length
payloads, loss counters, and TShark decoding. The 6.8/64 KiB kernel also enabled
kernel pointer authentication. Hardware and kernel BTI remain unvalidated.

With USB_MON disabled, both page sizes passed on 6.6.142, and 4 KiB passed on
6.8. Independent tcpdump comparison passed with 6.6.142/4 KiB and 6.8/64 KiB:
each SG/audio run matched 34 events (17 URBs), 516,238 payload bytes, and 256
reference ISO descriptors. All ten corrupted captures were rejected. The extra
control events relative to x86_64 are captured and compared too; they are not
discarded to force equal event counts across platforms. usbmon/libpcap's
documented truncation boundaries remain explicit; the independent fixture still
checks every byte of both 2,097,664-byte usbscope payloads and all 137 descriptors.

The arm64 4 KiB/64 KiB SG path combines a readable running kernel configuration
with CO-RE structure sizes. Missing/unsupported layout information disables SG
and reports affected events as loss. The configuration tests reject page-size
mismatches and tagged KASAN. The live suite mutates real object metadata to check
wrong-architecture and configuration-ABI rejection. Guest raw replay and pcapng
filtering match the x86_64 host byte for byte. The forced-loss fixture uses one
guest page and pauses its reader, removing the previous 4 KiB assumption.

The package script builds x86_64/aarch64 Linux GNU archives with a matching BPF
object; cross builds do not overwrite the native development object. The VM
workflow exercises these release artifacts in twelve configurations, including
both USB_MON states and separate contiguous-buffer comparisons. At this stage the hosted
workflow had not yet run. Reproduction instructions are in [platforms.md](platforms.md).

## Remaining validation and scope

- Physical controllers and DMA bounce/copyback paths need hardware testing.
- Live ISO IN, interrupt traffic, separately allocated SG chains, and HCD enqueue
  failure paths need dedicated kernel fixtures; existing coverage must not be
  treated as evidence for those cases.
- arm64 physical devices, kernel BTI, 16 KiB pages, and VA widths other than 48
  are not validated. SG supports SPARSEMEM_VMEMMAP on x86_64 and arm64; other
  memory models and tagged KASAN SG memory remain unsupported.
- Post-DMA observation uses kernel-internal hook ordering and readable symbol
  addresses. Other kernel versions/configurations require regression testing.
- Device context is an initial snapshot. Hotplug/alternate-setting timelines,
  UAC feedback decoding, and PCM/WAV export are future work.
- Full-length capture does not guarantee lossless capture at every data rate.
  Ring capacity, disk space, temporary storage, and capture-format/reader limits
  remain resource constraints; errors and incomplete events are reported.

## P5.1: newer ARM kernel layouts

Upstream Linux 6.9 changed `VMEMMAP_START` and stopped rounding `sizeof(struct
page)` up to a power of two when sizing that region. This preprocessor constant
cannot be relocated through BTF. Userspace selects the upstream layout using the
running release; the C shim still obtains the actual `struct page` size through
CO-RE. The shared configuration grows to 72 bytes, so the existing BPF metadata
check rejects older, incompatible objects. Vendor backports of this layout change
under an older release number need separate validation.

The same ARM BPF object passed SG/audio/filter/loss e2e and independent tcpdump
comparison on 6.6.142/4 KiB and 6.18.52/64 KiB. The latter also passed the separate
contiguous-buffer comparison. x86_64 6.6.142 with USB_MON disabled passed the full
suite after the configuration ABI change. All normal captures reported zero loss.

The kernel builder now clears competing ARM page-size and VA-width choices before
selecting them, then verifies the resolved configuration. Newer kernels default
to 52-bit VA; a job labeled VA48 must actually boot a VA48 kernel.

## P5.2: regular kernel matrix

At this stage, the matrix defined 12 PR/main jobs and 36 nightly/full jobs. Each
architecture is built once; all kernel jobs consume the same release and probe
artifacts. The guest runner accepts prebuilt smoke programs and ISO modules, and
asserts the booted release and page size as well as USB_MON and BTF availability.
Kernel caches contain only the boot image, fixture module, config, and checked
metadata. SHA-256-pinned sources, exact cache identities, toolchain fingerprints,
bounded download retries, and an official fallback mirror make failures reproducible.

Eight CI contract tests cover matrix completeness, invalid pins, cache identity,
corruption, mismatched config, rejected unverified sources, and download fallback.
Actionlint with ShellCheck passes, including all shell helpers. Negative checks
confirmed the aggregate status rejects failed/skipped/cancelled jobs and that
logging through `tee` preserves failure through the explicit Bash `pipefail` mode.

The exact cached-bundle path passed full x86_64 6.18.52 e2e with Cargo, Clang,
bpf-linker, and make replaced by failing stubs. ARM 6.18.52/64 KiB passed both
SG/audio and contiguous tcpdump comparison through the same CI wrapper.
Linux 6.12.110 passed on ARM/4 KiB with USB_MON=n and x86_64 with USB_MON=y;
the latter also passed both tcpdump comparison suites. Rust tests, Clippy, format
checks, and all 23 CLI/TShark e2e cases passed. At this stage the hosted workflow had not yet run.

## P5.3: current stable verifier and final regression

Linux 7.2.6 rejected the earlier object while checking a variable-length copy
into a ring reservation: its callback analysis reached a 4 KiB reservation with
a 16 KiB copy size. A volatile reload of the local length keeps the explicit
per-reservation bounds check in the generated program, independent of LLVM's
caller-branch folding. Reservation sizes and the full-length capture policy are
unchanged; no payload truncation or allowed-failure job was added.

After that change, one final BPF object per architecture passed full e2e across
6.6.142, 6.8, 6.12.110, 6.18.52, and 7.2.6. The ten concrete configurations are
listed in [ci.md](ci.md). Normal captures had zero ring/read/unsupported/state
losses; forced-loss captures failed as expected. Every USB_MON=y case passed the
SG/audio comparison and all ten corruption checks. The x86_64 6.12.110 and ARM
6.18.52/7.2.6 cases also passed contiguous capture comparison and its eight
corruption checks. Each direction retained the complete 2,097,664-byte payload,
and ISO metadata retained all 137 frames despite the reference's 128-frame limit.

Release and VM-helper archives were extracted into fresh directories. ELF
architecture, checksums, executable modes, documentation, library symlinks, and
complete guest dependency assembly were verified for both architectures.

## P6: arm64 big endian

`aarch64_be` now builds a big-endian Rust CLI and a `bpfeb` object with matching
C CO-RE accessors. Kernel structures, map values, predicates, and counters retain
native byte order. Ring records, build metadata, raw archives, and pcapng use
explicit little-endian encoding; USB setup and payload bytes are unchanged.
The raw ABI remains version 1. The loader rejects the wrong byte order before
attachment, alongside architecture and configuration ABI checks.

Live testing exposed four implementation/toolchain assumptions that were fixed:

- USB VID/PID and the mass-storage fixture's CBW fields need USB byte order.
- By-value metadata conversion exceeded the BPF combined stack limit on big
  endian. Converting initialized metadata in the ring reservation reduced the
  emitting function's stack from 344 to 272 bytes.
- The old userspace nightly produced incorrect ARM big-endian NEON string
  searches in ELF parsing. Userspace now uses `nightly-2026-09-18`/`build-std`;
  the independently pinned BPF toolchain is unchanged.
- crc32fast's ARM native-word CRC path rejected valid `/proc/config.gz` data.
  Big-endian flate2 uses zlib-rs instead. An independent gzip vector and damaged
  checksum exercise this boundary in unit tests. Rustix uses its libc backend.

The pinned Bootlin SDK's shared loader assumes 4 KiB pages. Big-endian release
and VM executables are statically linked with 64 KiB segment alignment, making
the same binaries usable on both tested page sizes. VM tools come from verified
BusyBox/libpcap/tcpdump source archives. libpcap is pinned to 1.10.4, matching the
LE baseline: 1.10.5 omitted descriptors from the original length of an ISO
submission. The comparator continues to reject `caplen > len` and now decodes
big-endian reference pcap and USB headers.

The same big-endian object and CLI passed full SG/audio/filter/replay/loss tests
on **6.6.142/4 KiB/USB_MON=n** and **6.12.110/64 KiB/USB_MON=y**. Captures retained
all 2,097,664 bytes in each direction and all 137 ISO descriptors. Normal capture
counters were zero for ring/read/unsupported/state loss. Guest and x86_64 host
replay/filter output matched byte for byte; TShark decoded the files. The 6.12
run additionally passed SG/audio and contiguous tcpdump comparisons, including
ten and eight deliberately corrupted capture checks respectively. Little-endian
x86_64 6.6.142/4 KiB and arm64 6.12.110/4 KiB passed the full USB_MON=n suite after
the encoding changes. Seven Rust tests and all 23 CLI/TShark cases passed on
both the native and actual big-endian binaries.

All three release/helper packages built through `scripts/ci/build-userspace.sh`.
Fresh extraction verified checksums, ELF byte order, executable modes, and both
language guides. The packaged big-endian release passed the CI wrapper's full
SG/audio and contiguous comparisons against the verified 6.12.110/64 KiB bundle.

The regular matrix expands to **16 PR/main and 52 nightly/full VM jobs**, with
separate x86_64, aarch64, and aarch64_be release builds. Big-endian kernels cover
4 KiB/64 KiB and USB_MON=n/y on 6.6.142, 6.6.157, 6.8, and 6.12.110. The pinned
6.18.52 and 7.2.6 require `BROKEN` for arm64 big endian and remain LE-only.
The manifest records that restriction; cache verification and guest assertions
check byte order. Nine CI contract tests, Actionlint, ShellCheck, formatting,
and native Clippy pass. At this stage hosted Actions had not yet run; additional matrix cells
and physical hardware remain distinct from the local evidence above.

## P7: GitHub Actions validation

The repository is hosted at [swananan/usbscope](https://github.com/swananan/usbscope).
The first hosted runs exposed two CI setup assumptions:

- Dated Rust nightlies are toolchain inputs, not Git refs of
  `dtolnay/rust-toolchain`. The workflow now uses the action's `master` ref with
  explicit pinned `toolchain` inputs.
- The pinned newer arm64 kernels hide `CPU_BIG_ENDIAN` behind `BROKEN`, so
  `.config` omits even its disabled line. Kernel builds, cache verification, and
  guest assertions now check the selected `CONFIG_CPU_LITTLE_ENDIAN=y` option.
  Regression tests accept the omitted option while still rejecting a big-endian
  kernel in a little-endian cache.

The second fix passed all 11 CI contract tests, Actionlint, ShellCheck, and a
local ARM 6.18.52/64 KiB/USB_MON=y run with SG/audio and contiguous tcpdump
comparisons, including all ten and eight corruption checks.

On 2026-09-20, commit
[`4150a4a`](https://github.com/swananan/usbscope/commit/4150a4a0551e8b96356f253879aef82dd78a7a31)
passed [userspace checks](https://github.com/swananan/usbscope/actions/runs/35508748463)
and the complete [16-configuration PR/main matrix](https://github.com/swananan/usbscope/actions/runs/35508748487).
All three architecture builds and the aggregate check passed. The big-endian
build also ran its Rust tests and all 23 CLI/TShark cases on the big-endian binary.
Each architecture's packaged CLI/BPF object was reused across its kernel jobs.

The [52-configuration full run](https://github.com/swananan/usbscope/actions/runs/35509184246)
tests the same commit across all pinned kernels. Its job conclusions, logs, and
capture artifacts provide the per-configuration results; see the
[CI validation record](ci.md#validation-status) for the run index. These QEMU
results are separate from the physical-controller coverage still listed above.
