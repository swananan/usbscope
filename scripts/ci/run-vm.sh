#!/bin/bash
# Run exactly the packaged objects from build-userspace.sh, without Cargo/Clang.
set -euo pipefail
cd "$(dirname "$0")/../.."
capture_arch=${1:?usage: run-vm.sh ARCH KERNEL_VERSION PAGES USBMON [BUNDLE]}
version=${2:?}
pages=${3:?}
usbmon=${4:?}
bundle=${5:-target/ci/kernel}
output=${VM_OUTPUT_DIR:-target/ci/results}
python3 scripts/ci/kernel.py verify --version "$version" --arch "$capture_arch" \
    --pages "$pages" --usbmon "$usbmon" --bundle "$bundle"
release="target/dist/usbscope-$capture_arch-linux"
host_release="target/dist/usbscope-$(uname -m)-linux"
(cd "$release" && sha256sum --check SHA256SUMS)
(cd "$host_release" && sha256sum --check SHA256SUMS)
kernel_release=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["kernel_release"])' "$bundle/metadata.json")
extra=()
if [[ "$capture_arch" != "$(uname -m)" ]]; then
    extra+=(--guest-root "target/ci/userspace/$capture_arch/guest-root")
fi
if [[ "$usbmon" = y ]]; then extra+=(--compare-tcpdump); fi
common=(--arch "$capture_arch" --live --release --kernel "$bundle/kernel"
    --expected-kernel-release "$kernel_release" --expected-page-kib "${pages%K}"
    --binary "$release/usbscope" --bpf-object "$release/usbscope.bpf.o"
    --probe-binary "target/ci/userspace/$capture_arch/probe-smoke"
    --host-binary "$host_release/usbscope" "${extra[@]}")
python3 tests/vm/run.py "${common[@]}" --audio --filters --sg --iso-module "$bundle/usbscope_iso.ko" \
    --log "$output/sg-audio.log" --artifacts "$output/sg-audio"
if [[ "$usbmon" = y ]]; then
    python3 tests/vm/run.py "${common[@]}" \
        --log "$output/contiguous.log" --artifacts "$output/contiguous"
fi
