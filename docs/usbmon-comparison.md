# Differential USB capture e2e

The VM suite can run usbscope and **tcpdump as independent live collectors**.
Tcpdump opens the kernel's `/dev/usbmon0` through libpcap. TShark subsequently
decodes both output files. This is separate from merely asking TShark to decode
usbscope's own output.

The ordinary VM configuration still has `CONFIG_USB_MON=n` and checks that at
boot. The comparison configuration requires `CONFIG_USB_MON=y` and checks both
the config and the device node. First [build the CLI and BPF object](development.md#build-and-test),
then keep the kernel build directories separate:

```sh
USBMON=y tests/vm/build-kernel.sh /path/to/linux-source target/vm-kernel-usbmon
python3 tests/vm/run.py --release --live --audio --filters --sg \
  --compare-tcpdump \
  --kernel target/vm-kernel-usbmon/arch/x86/boot/bzImage \
  --log target/vm-usbmon.log --artifacts target/vm-usbmon-artifacts
```

In addition to the ordinary VM dependencies, install `tcpdump` for the guest
architecture. Native runs use the host copy; cross runs use `--guest-root`, as
described in the [platform guide](platforms.md). The runner copies it and its
libraries into the temporary guest. Capture runs only
inside QEMU; host root, host usbmon, and physical USB devices are not needed.

## Collection and comparison

The guest starts tcpdump on `usbmon0` with `-s 0 -U`, waits for its readiness
message, starts usbscope, and waits for all BPF probes to attach. Only then does
it generate the USB fixture traffic. Tcpdump uses a guest-only account and an
output descriptor opened by the shell. Both collectors stop cleanly, and tcpdump
must report zero kernel drops and no queued/unwritten packets.

The first live capture contains control traffic, bulk IN/OUT transfers of
2,097,664 bytes, and, with `--audio`, a sparse 137-frame ISO OUT transfer.
The usual independent fixture checks, filter scenarios, archive replay, and
forced ring-loss scenario also run; tcpdump comparison covers the first,
unfiltered capture.

The Python checker independently reads tcpdump's pcap and usbscope's pcapng;
it does not import the product's readers. It accepts both byte orders for the
tcpdump pcap and its USB pseudoheaders; usbscope output stays little endian.
It requires matching endpoint sets,
per-endpoint submission counts, submission/completion pairing, phase, status,
transfer length, flags, setup bytes, and applicable interval/ISO metadata.

IDs are normalized per submission because usbmon uses reusable URB pointers and
usbscope allocates fresh IDs. Per-endpoint submission order pairs the two traces;
global ordering across independent endpoints is not required. Absolute timestamps
are not compared for equality because the hooks run at different points. Each
trace must put completion after submission; the report records the maximum
observed timestamp difference. This is a correctness test, not a latency or
throughput benchmark.

## Baseline truncation is explicit

Two baseline limits need different treatment from capture loss:

- The tested libpcap 1.10.4 reduces the USB snapshot to **245,824 bytes**, including
  the 64-byte header. Each large bulk payload therefore retains 245,760 bytes.
  The checker derives the expected prefix length from the file snapshot, requires
  that exact amount, and compares every retained byte. It also requires a snapshot
  large enough to retain at least 64 KiB per large payload. An arbitrary short
  reference packet is a failure.
- Linux 6.6.142 and 6.8 usbmon export at most **128 ISO descriptors**, while the
  fixture has 137 frames. The checker requires exactly `min(total_frames, 128)`
  descriptors and compares every exported descriptor. An unexplained shorter
  list is a failure.

For ISO data, usbmon copies buffer gaps while usbscope zero-fills them. Comparison
covers valid regions described by the reference's descriptors, excluding padding.
The independent driver fixture still validates all 137 usbscope frames, including
those omitted from the baseline, and the entire bulk payload in both directions.
Passing the comparison does not turn a truncated baseline into a full-length one.

These rules follow [libpcap's USB ring sizing](https://github.com/the-tcpdump-group/libpcap/blob/libpcap-1.10.4/pcap-usb-linux.c)
and [the kernel's usbmon binary implementation](https://github.com/torvalds/linux/blob/v6.8/drivers/usb/mon/mon_bin.c).
The checker targets the x86_64 and arm64 VM fixtures and explicitly rejects unsupported
capture encodings. Update its baseline assumptions with evidence when changing
the kernel matrix or reference collector.

## Regression coverage and artifacts

GitHub Actions uses [pinned kernel profiles](ci.md) with USB_MON both disabled and enabled,
across x86_64 and arm64/4 KiB/64 KiB, including big endian on eligible kernels:
16 jobs on pull requests and pushes to `main`, and 52 in the nightly/full profile.
The [big-endian guide](big-endian.md) records its pinned reference tools and coverage.
Manual dispatch selects either
profile and defaults to full. The expanded hosted workflow has not yet run. The enabled
jobs require the tcpdump comparison; they do not skip it if a tool is missing.
Both configurations retain the full original live suite.
Enabled jobs also run a second comparison without `--sg` or `--audio`, covering
large contiguous bulk buffers as well as the SG/audio case.

After a successful audio comparison, ten negative checks damage copies of the actual
captures: remove a completion or whole URB, duplicate a URB, alter status/setup/
payload/ISO metadata, truncate usbscope beyond the reference's captured prefix,
or shorten the reference payload/descriptor list. Each must be rejected. Runs
without audio perform the eight applicable checks.

Artifacts include `live.pcapng`, `tcpdump.pcap`, `tcpdump.log`, collector versions,
`comparison.json` with comparison and truncation counts, and
`comparison-negative.json` listing the rejected mutations. CI uploads the artifact
directory and guest log even on failure. A saved run can be checked again with:

```sh
python3 tests/vm/compare.py target/vm-usbmon-artifacts --audio
python3 tests/vm/test_compare.py target/vm-usbmon-artifacts
```

The baseline currently covers control, bulk (including SG), and ISO OUT. It does
not establish physical-controller behavior, live ISO IN, interrupt traffic, or
HCD enqueue-error equivalence.
