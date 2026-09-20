# Kernel CI

The workflow tests real USB I/O in QEMU, including kernels built with
`CONFIG_USB_MON=n`. Merely compiling for arm64 or running a CLI fixture does not
count as kernel coverage.

## Matrix and triggers

Each kernel runs on three targets: x86_64/4 KiB, arm64/4 KiB, and arm64/64 KiB.
Kernels that permit arm64 big endian also run on aarch64_be/4 KiB and
aarch64_be/64 KiB. Each target runs with USB_MON disabled and enabled, giving
six or ten jobs per kernel. ARM uses 48-bit VA; builder and guest assertions
check the selected settings, including kernel and process byte order.

| Kernel pin | Purpose | ARM big endian | PR / main push | Nightly / full |
| --- | --- | --- | --- | --- |
| 6.6.142 | Keep the minimum validated release from regressing | Yes | Yes | Yes |
| 6.6.157 | Current 6.6 LTS patch | Yes | | Yes |
| 6.8 | Retain the original cross-kernel regression target | Yes | | Yes |
| 6.12.110 | 6.12 LTS | Yes | | Yes |
| 6.18.52 | 6.18 LTS | No: upstream `BROKEN` dependency | Yes | Yes |
| 7.2.6 | Current stable | No: upstream `BROKEN` dependency | | Yes |
| **Jobs** | | | **16** | **52** |

The [big-endian guide](big-endian.md) explains the kernel restriction and separate
toolchain. The manifest records this capability explicitly; unsupported requests
fail before building, and no job bypasses the kernel's `BROKEN` dependency.

Pins were checked against [kernel.org releases](https://www.kernel.org/releases.json)
on 2026-09-20. The manifest is [scripts/ci/kernels.json](../scripts/ci/kernels.json);
the matrix generator is shared by local checks and Actions. The scheduled run is
daily at 03:17 UTC (11:17 Asia/Shanghai). Manual dispatch offers `full` (default)
and `pr`. The matrix uses `fail-fast: false`, at most six concurrent VM jobs,
and a 45-minute timeout per VM job. There are no allowed failures or missing-tool
skips. Add `kernel-e2e` and the separate `checks` workflow's `userspace` job to
branch protection when configuring the GitHub repository.

## What we took from Aya

The reference is [Aya's workflow at 15593549](https://github.com/aya-rs/aya/blob/15593549d93cd39decf008f6d859fd054ba40bcf/.github/workflows/ci.yml).
Its VM matrix covers 5.10, 5.15, 6.1, 6.6, 6.12, and 6.18 on amd64 and arm64;
ARM kernels run in separate jobs. We follow its LTS coverage, independent jobs,
default-branch cache writes, and aggregate required check.

usbscope starts at its validated 6.6.142 baseline. Aya's older kernel targets do
not establish compatibility for this application's helpers or USB hooks. We
also need USB_MON=n/y, ARM page-size variants, and a module built for each exact
kernel. Thus we build small upstream kernels instead of using Aya's Ubuntu
Mainline packages. All runners are `ubuntu-24.04` x86_64; ARM is cross-compiled
and runs with QEMU TCG, using the same rootless path exercised locally. No host
USB device, host BPF attachment, KVM, or privileged VM runner is required.

## Build once, test across kernels

Three build jobs produce architecture/endian-specific release archives and VM helpers.
Every kernel job downloads these artifacts. All kernels of a target use
the **same CLI and BPF bytes**, exercising CO-RE without per-kernel recompilation.
Little-endian ARM guests use signature-verified Ubuntu 24.04 packages. Big-endian
guests use the checksum-pinned Bootlin SDK and statically built BusyBox/tcpdump.
The big-endian build job additionally runs unit tests and all 23 CLI/TShark e2e
cases through qemu-user.
Tar archives preserve executable modes and library symlinks across artifact
upload/download. The x86_64 CLI also performs offline verification of ARM captures.

Kernel sources use kernel.org's CDN with retries, bounded stall/transfer timeouts,
and a fallback to `www.kernel.org`. Downloads are SHA-256 checked against the
committed manifest before extraction. A cache contains only the boot image,
matching ISO module, resolved config, and JSON metadata with file checksums.
The key includes source digest, target, pages, USB_MON, compiler/binutils/pahole
versions, kernel builder, and fixture sources. It never restores a partial-key
match across configurations. Only the default branch writes caches, so fork PRs
can reuse shared entries without filling the repository with private variants.

Restored bundles are verified before boot. The guest independently asserts its
release, page size, byte order, USB_MON state, and readable BTF. Cache hits need no kernel
source tree or Rust/BPF compilation. Build jobs retain Cargo and linker caches;
complete kernel build trees are deliberately excluded from the kernel cache.

## Required tests and diagnostics

Every VM runs probe smoke, architecture/endian/ABI rejection, control and bulk traffic,
full 2,097,664-byte SG payloads in both directions, 137 sparse ISO audio frames,
filter checks, raw replay, guest/host pcapng equivalence, TShark decoding, and
forced ring loss. USB_MON=y also requires independent tcpdump comparison and
negative comparison tests, followed by a separate contiguous-buffer comparison.
The [comparison guide](usbmon-comparison.md) documents the reference's truncation
limits; usbscope's full payload is still checked against the independent fixture.

All jobs upload logs and available captures on failure as well as success.
`vm-e2e-<arch>-<pages>-<version>-usbmon-<n|y>` contains `sg-audio/` and, where
applicable, `contiguous/` captures, guest logs, comparison JSON, kernel config,
and metadata. Build output is in `kernel-build.log`, test output in `test.log`.
The job summary records the release checksums and kernel identity. Artifacts
expire after seven days. `kernel-e2e` fails if preparation, any build, or any
selected VM job fails or is skipped.

## Local reproduction and updates

Install the [Rust/BPF toolchains](development.md#build-and-test) and the VM
dependencies from the [platform guide](platforms.md). Kernel building also requires GCC, flex, bison, bc,
libelf/libssl development packages, and pahole (`dwarves` on Ubuntu).

```sh
python3 scripts/ci/matrix.py --profile full
python3 -m unittest discover -s scripts/ci -p 'test_*.py' -v
scripts/ci/build-userspace.sh x86_64
scripts/ci/build-userspace.sh aarch64
JOBS=4 python3 scripts/ci/kernel.py build --version 6.18.52 \
  --arch aarch64 --pages 64K --usbmon y
scripts/ci/run-vm.sh aarch64 6.18.52 64K y
```

The kernel bundle defaults to `target/ci/kernel`; the build work directory is
`target/ci/kernel-work`. Use `--bundle`/`--work-dir` for separate builds, and pass
the bundle as the fifth argument to `run-vm.sh`. `VM_OUTPUT_DIR` selects the result
directory (default `target/ci/results`). Finish a kernel build before running its
tests. To rerun a cached job, just call `run-vm.sh`; it verifies the bundle first.

When updating a kernel, edit its version and the tarball digest from kernel.org's
`v6.x/sha256sums.asc` or `v7.x/sha256sums.asc`, then run the relevant architectures
and comparison cases before committing. Check its arm64 `CPU_BIG_ENDIAN`
dependencies and set `arm64_big_endian` accordingly. Keep 6.6.142 pinned as the lower bound.
Do not resolve a moving `latest` inside PR jobs: a failed run must identify the
exact source used. Nightly runs cover the committed pins; upstream release bumps
still require a manifest update. Update this table, the
[runtime coverage](platforms.md#runtime-coverage), and any affected validation
records with it.

## Validation status

The hosted workflow has not yet run: this checkout has no Git remote configured.
Local runs verify the workflow's scripts and QEMU test path; they do not establish
that every one of the 52 hosted combinations has passed. Before the big-endian
extension, one BPF object per little-endian architecture passed these ten local configurations:

| Kernel | x86_64 | arm64 |
| --- | --- | --- |
| 6.6.142 | 4 KiB, USB_MON=n | 4 KiB, USB_MON=y |
| 6.8 | 4 KiB, USB_MON=y | 64 KiB, USB_MON=y |
| 6.12.110 | 4 KiB, USB_MON=y | 4 KiB, USB_MON=n |
| 6.18.52 | 4 KiB, USB_MON=n | 64 KiB, USB_MON=y |
| 7.2.6 | 4 KiB, USB_MON=n | 64 KiB, USB_MON=y |

Every cell passed SG, audio, filters, replay, TShark, and loss checks. All `y`
cells passed the independent SG/audio comparison. The 6.12.110 x86_64 and
6.18.52/7.2.6 arm64 cases additionally passed the separate contiguous comparison.
The final objects include fixes for the ARM 6.9+ vmemmap layout and the ring
reservation bounds exposed by the 7.2 verifier. Exact evidence and remaining
hardware/traffic limitations are recorded in [implementation.md](implementation.md).

After adding big-endian support, the arm64 big-endian object passed 6.6.142/4 KiB
with USB_MON=n and 6.12.110/64 KiB with USB_MON=y. Both passed SG, audio, filters,
cross-endian replay, TShark, and forced-loss tests. The latter also passed the
SG/audio and contiguous tcpdump comparisons with corruption checks. The same
CLI/BPF bytes were used in both kernels. Little-endian x86_64 6.6.142/4 KiB and
arm64 6.12.110/4 KiB were rerun with USB_MON=n after the encoding changes.
Other newly added big-endian combinations await the hosted matrix.
