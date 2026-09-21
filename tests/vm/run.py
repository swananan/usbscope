#!/usr/bin/env python3
"""Rootless QEMU e2e; optionally compare live capture with tcpdump/usbmon."""
import argparse
import os
from pathlib import Path
import platform
import shutil
import shlex
import struct
import subprocess
import tempfile

from guest import Guest

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser()
parser.add_argument('--arch', choices=['x86_64', 'aarch64', 'aarch64_be'], default=platform.machine())
parser.add_argument('--kernel', type=Path)
parser.add_argument('--bpf-object', type=Path)
parser.add_argument('--binary', type=Path, help='capture CLI to install, for testing an extracted release')
parser.add_argument('--probe-binary', type=Path, help='prebuilt probe-smoke for the guest architecture')
parser.add_argument('--host-binary', type=Path, help='prebuilt native CLI for offline validation')
parser.add_argument('--iso-module', type=Path, help='prebuilt ISO fixture for this exact guest kernel')
parser.add_argument('--expected-kernel-release', help='fail if the guest boots a different kernel release')
parser.add_argument('--expected-page-kib', type=int, choices=[4, 16, 64], help='assert the guest page size')
parser.add_argument('--guest-root', type=Path,
                    help='guest userspace from prepare-guest.py or prepare-big-endian.py')
parser.add_argument('--timeout', type=int, default=300)
parser.add_argument('--log', type=Path, default=ROOT / 'target/vm-e2e.log')
parser.add_argument('--live', action='store_true', help='validate full payload capture through the CLI')
parser.add_argument('--artifacts', type=Path, default=ROOT / 'target/vm-artifacts')
parser.add_argument('--audio', action='store_true', help='include a 137-frame sparse ISO audio URB')
parser.add_argument('--filters', action='store_true', help='compare live kernel prefiltering and exact userspace filtering')
parser.add_argument('--sg', action='store_true', help='use asynchronous usbfs scatter-gather buffers for large URBs')
parser.add_argument('--release', action='store_true', help='test the optimized userspace binary')
parser.add_argument('--compare-tcpdump', action='store_true',
                    help='capture the same transfers with tcpdump (requires a USB_MON=y kernel)')
args = parser.parse_args()
cross = args.arch != platform.machine()
if cross and not args.guest_root:
    parser.error('cross-architecture runs require --guest-root (see prepare-guest.py / prepare-big-endian.py)')
arm64 = args.arch in ('aarch64', 'aarch64_be')
big_endian = args.arch == 'aarch64_be'
kernel_arch = 'arm64' if arm64 else 'x86'
image = 'Image' if arm64 else 'bzImage'
args.kernel = args.kernel or ROOT / f'target/vm-kernel/arch/{kernel_arch}/boot/{image}'
if not args.kernel.is_file():
    parser.error(f'build the guest kernel first: {args.kernel}')
args.bpf_object = args.bpf_object or ROOT / f'target/{args.arch}/usbscope.bpf.o'
if not args.bpf_object.is_file():
    parser.error(f'build the BPF object first: scripts/build-ebpf.sh {args.arch}')
if (args.audio or args.filters or args.sg or args.compare_tcpdump) and not args.live:
    parser.error('--audio, --filters, --sg, and --compare-tcpdump require --live')
profile = 'release' if args.release else 'debug'
build_flags = ['--release'] if args.release else []
target = f'{args.arch}-unknown-linux-gnu'
guest_flags = build_flags + (['--target', target] if cross else [])
guest_build = ROOT / 'target' / target / profile if cross else ROOT / 'target' / profile
build_environment = dict(os.environ)
prefix = os.environ.get('CROSS_COMPILE',
                        'aarch64_be-buildroot-linux-gnu-' if big_endian else f'{args.arch}-linux-gnu-')
compiler = prefix + 'gcc' if cross else 'gcc'
module_flags = [f'ARCH={kernel_arch}']
if cross:
    build_environment.setdefault(f'CARGO_TARGET_{target.upper().replace("-", "_")}_LINKER', compiler)
    module_flags += [f'CROSS_COMPILE={prefix}']
build_command = (['scripts/build-userspace.sh', args.arch] + build_flags if cross
                 else ['cargo', 'build', '--locked'] + guest_flags)
if not args.probe_binary:
    subprocess.run(build_command + ['--example', 'probe-smoke'],
                   cwd=ROOT, env=build_environment, check=True)
    args.probe_binary = guest_build / 'examples/probe-smoke'
if args.live:
    if not args.binary:
        subprocess.run(build_command, cwd=ROOT, env=build_environment, check=True)
        args.binary = guest_build / 'usbscope'
    # Offline validation runs on the host, even when capture runs on another CPU.
    if not args.host_binary:
        if cross:
            subprocess.run(['cargo', 'build', '--locked'] + build_flags, cwd=ROOT, check=True)
            args.host_binary = ROOT / f'target/{profile}/usbscope'
        else:
            args.host_binary = args.binary
    args.artifacts.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(prefix='usbscope-vm-', dir=ROOT / 'target') as temp:
    work = Path(temp)
    fixture = work / 'usb-fixture'
    fixture_flags = ['-static', '-Wl,-z,max-page-size=65536'] if big_endian else []
    subprocess.run([compiler, '-O2', '-Wall', '-Werror', *fixture_flags, '-o', str(fixture),
                    str(ROOT / 'tests/vm/usb-fixture.c')], check=True)
    if args.audio and not args.iso_module:
        module_dir = work / 'module'
        shutil.copytree(ROOT / 'tests/vm/kernel', module_dir)
        kernel_build = args.kernel.resolve().parents[3]
        # `make modules` can rebuild vmlinux (including its BTF) after a compiler
        # or configuration change. Refresh the boot image in the same build, or
        # the new module's split BTF may refer to a different kernel's type IDs.
        subprocess.run(['make', '-s', '-C', str(kernel_build), '-j4', *module_flags,
                        image, 'modules'], check=True)
        subprocess.run(['make', '-s', '-C', str(kernel_build), *module_flags, f'M={module_dir}', 'modules'], check=True)
        args.iso_module = module_dir / 'usbscope_iso.ko'
    tree = work / 'root'
    tree.mkdir()
    for directory in ['bin', 'lib', 'dev', 'proc', 'sys', 'tmp', 'run', 'out']:
        (tree / directory).mkdir()
    # Some cross SDK loaders search /lib64. Dependencies are installed in /lib.
    (tree / 'lib64').symlink_to('lib')

    guest = Guest(tree, args.guest_root or Path('/'), args.arch)
    guest.binary(guest.find('busybox'), '/bin/busybox')
    guest.binary(args.probe_binary, '/probe-smoke')
    guest.binary(fixture, '/usb-fixture')
    if args.live:
        guest.binary(args.binary, '/usbscope')
    if args.compare_tcpdump:
        guest.binary(guest.find('tcpdump'), '/tcpdump')
        (tree / 'etc').mkdir()
        (tree / 'etc/passwd').write_text('root:x:0:0:root:/root:/bin/sh\ncapture:x:65534:65534:capture:/tmp:/bin/sh\n')
        (tree / 'etc/group').write_text('root:x:0:\ncapture:x:65534:\n')
        (tree / 'etc/nsswitch.conf').write_text('passwd: files\ngroup: files\n')
    guest.install(args.bpf_object, '/usbscope.bpf.o')
    if args.live:
        # Mutate only the build metadata of a real object. Both checks must fail
        # before attachment, even though the program's ELF/BTF remain valid.
        original = args.bpf_object.read_bytes()
        marker = b'USBSBPF1'
        if original.count(marker) != 1:
            raise SystemExit('missing or ambiguous BPF build metadata')
        offset = original.index(marker)
        wrong_arch = bytearray(original)
        struct.pack_into('<I', wrong_arch, offset + 8, 62 if arm64 else 183)
        (tree / 'wrong-arch.bpf.o').write_bytes(wrong_arch)
        wrong_abi = bytearray(original)
        wrong_abi[offset + 12] ^= 8
        (tree / 'wrong-abi.bpf.o').write_bytes(wrong_abi)
        # A valid empty ELF for the opposite byte order must be rejected before
        # inspecting capture metadata or loading programs into the kernel.
        encoding, order = (1, '<') if big_endian else (2, '>')
        ident = b'\x7fELF' + bytes([2, encoding, 1]) + bytes(9)
        wrong_endian = struct.pack(order + '16sHHIQQQIHHHHHH', ident, 1, 247, 1,
                                   0, 0, 0, 0, 64, 0, 0, 64, 0, 0)
        (tree / 'wrong-endian.bpf.o').write_bytes(wrong_endian)
    if args.audio:
        guest.install(args.iso_module, '/usbscope_iso.ko')
    init = tree / 'init'
    init.write_text('''#!/bin/busybox sh
/bin/busybox --install -s /bin
export LC_ALL=C
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
fail() {
    echo USBSCOPE_VM_FAIL
    if test -n "${probe:-}"; then
        cat /proc/$probe/stack /proc/$probe/syscall /proc/$probe/status 2>/dev/null
    fi
    for log in /tmp/arch.log /tmp/abi.log /tmp/endian.log /out/*.log; do
        test ! -f "$log" || { echo "$log"; cat "$log"; }
    done
    reboot -f
}
zcat /proc/config.gz | grep -q '^# CONFIG_USB_MON is not set$' || fail
test -r /sys/kernel/btf/vmlinux || fail
sleep 1
/probe-smoke /usbscope.bpf.o &
probe=$!
for i in $(seq 1 600); do
    test -f /tmp/probe-ready && break
    kill -0 $probe 2>/dev/null || fail
    sleep 0.1
done
test -f /tmp/probe-ready || fail
/usb-fixture || fail
wait $probe || fail
cmp /tmp/probe-expected /tmp/probe-observed || fail
echo USBSCOPE_VM_PASS
reboot -f
''')
    endian = 'big' if big_endian else 'little'
    checks = ['uname -a', f'test "$(/usb-fixture --endian)" = {endian} || fail']
    if arm64:
        config = '^CONFIG_CPU_BIG_ENDIAN=y$' if big_endian else '^CONFIG_CPU_LITTLE_ENDIAN=y$'
        checks += [f'zcat /proc/config.gz | grep -q {shlex.quote(config)} || fail']
    checks += [f'echo USBSCOPE_ENDIAN_{endian.upper()}_PASS']
    if args.expected_kernel_release:
        checks += [f'test "$(uname -r)" = {shlex.quote(args.expected_kernel_release)} || fail']
    if args.expected_page_kib:
        checks += [f'test "$(/usb-fixture --page-kib)" = {args.expected_page_kib} || fail']
    init.write_text(init.read_text().replace('sleep 1\n', '\n'.join(checks) + '\nsleep 1\n', 1))
    if args.live:
        init.write_text(init.read_text().replace('/probe-smoke /usbscope.bpf.o &', '''
if /usbscope --bpf-object /wrong-arch.bpf.o --duration 0.01 2>/tmp/arch.log; then fail; fi
grep -q 'BPF object architecture mismatch' /tmp/arch.log || fail
if /usbscope --bpf-object /wrong-abi.bpf.o --duration 0.01 2>/tmp/abi.log; then fail; fi
grep -q 'BPF configuration ABI mismatch' /tmp/abi.log || fail
if /usbscope --bpf-object /wrong-endian.bpf.o --duration 0.01 2>/tmp/endian.log; then fail; fi
grep -q 'BPF object byte order mismatch' /tmp/endian.log || fail
echo USBSCOPE_OBJECT_GUARDS_PASS
/probe-smoke /usbscope.bpf.o &'''))
        init.write_text(init.read_text().replace('echo USBSCOPE_VM_PASS', '''
mount -t 9p -o trans=virtio,version=9p2000.L artifacts /out || fail
/usbscope --bpf-object /usbscope.bpf.o -w /out/live.pcapng --raw-output /out/live.usbraw --device-context /out/devices.json --iso-stats --ready-file /tmp/live-ready --duration 6 --fail-on-loss &
capture=$!
for i in $(seq 1 600); do
    test -f /tmp/live-ready && break
    kill -0 $capture 2>/dev/null || fail
    sleep 0.1
done
test -f /tmp/live-ready || fail
/usb-fixture --bulk || fail
wait $capture || fail
/usbscope -r /out/live.usbraw -w /out/guest-replay.pcapng --fail-on-loss || fail
cmp /out/live.pcapng /out/guest-replay.pcapng || fail
/usbscope -r /out/live.pcapng -w /out/guest-selected.pcapng 'bulk and in' || fail
ring_kib=$(/usb-fixture --page-kib) || fail
/usbscope --bpf-object /usbscope.bpf.o -B "$ring_kib" -w /out/loss.pcapng --raw-output /out/loss.usbraw --ready-file /tmp/loss-ready --duration 4 --fail-on-loss 2>/out/loss.log &
capture=$!
for i in $(seq 1 600); do
    test -f /tmp/loss-ready && break
    kill -0 $capture 2>/dev/null || fail
    sleep 0.1
done
test -f /tmp/loss-ready || fail
kill -STOP $capture || fail
/usb-fixture --bulk || fail
kill -CONT $capture || fail
if wait $capture; then fail; fi
grep -q 'capture contains lost or incomplete events' /out/loss.log || fail
sync
echo USBSCOPE_VM_PASS'''))
    if args.audio:
        init.write_text(init.read_text().replace('wait $capture || fail', '''
insmod /usbscope_iso.ko || fail
test "$(cat /sys/module/usbscope_iso/parameters/result)" = 0 || fail
cat /sys/module/usbscope_iso/parameters/actual_lengths > /out/iso-lengths.txt
cat /sys/module/usbscope_iso/parameters/frame_status > /out/iso-status.txt
wait $capture || fail''', 1))
    if args.filters:
        init.write_text(init.read_text().replace('sync\necho USBSCOPE_VM_PASS', '''
filter_capture() {
    name=$1
    expression=$2
    /usbscope --bpf-object /usbscope.bpf.o -w /out/$name.pcapng --ready-file /tmp/$name-ready --duration 3 --fail-on-loss "$expression" 2>/out/$name.log &
    capture=$!
    for i in $(seq 1 600); do
        test -f /tmp/$name-ready && break
        kill -0 $capture 2>/dev/null || fail
        sleep 0.1
    done
    test -f /tmp/$name-ready || fail
    /usb-fixture --bulk || fail
    wait $capture || fail
}
filter_capture filtered 'bulk and requested > 1000000 and event complete and latency >= 0ns'
filter_capture mixed 'bus 999 or payload contains 0x55534243'
sync
echo USBSCOPE_VM_PASS'''))
    if args.sg:
        init.write_text(init.read_text().replace('/usb-fixture --bulk', '/usb-fixture --sg'))
    if args.audio:
        init.write_text(init.read_text().replace('sync\necho USBSCOPE_VM_PASS', '''
iso_interface=
for entry in /sys/bus/usb/drivers/usbscope-iso-test/*:*; do
    test ! -L "$entry" || iso_interface=${entry##*/}
done
test -n "$iso_interface" || fail
echo "$iso_interface" > /sys/bus/usb/drivers/usbscope-iso-test/unbind || fail
/usbscope --bpf-object /usbscope.bpf.o -w /out/edges.pcapng --raw-output /out/edges.usbraw --ready-file /tmp/edges-ready --duration 4 --fail-on-loss 2>/out/edges.log &
capture=$!
for i in $(seq 1 600); do
    test -f /tmp/edges-ready && break
    kill -0 $capture 2>/dev/null || fail
    sleep 0.1
done
test -f /tmp/edges-ready || fail
echo 1 > /sys/module/usbscope_iso/parameters/overlap || fail
echo "$iso_interface" > /sys/bus/usb/drivers/usbscope-iso-test/bind || fail
test "$(cat /sys/module/usbscope_iso/parameters/result)" = 0 || fail
cat /sys/module/usbscope_iso/parameters/actual_lengths > /out/overlap-lengths.txt
cat /sys/module/usbscope_iso/parameters/frame_status > /out/overlap-status.txt
echo "$iso_interface" > /sys/bus/usb/drivers/usbscope-iso-test/unbind || fail
echo 0 > /sys/module/usbscope_iso/parameters/overlap || fail
echo 1 > /sys/module/usbscope_iso/parameters/exercise_errors || fail
echo "$iso_interface" > /sys/bus/usb/drivers/usbscope-iso-test/bind || fail
test "$(cat /sys/module/usbscope_iso/parameters/result)" = 0 || fail
cat /sys/module/usbscope_iso/parameters/actual_lengths > /out/cancel-lengths.txt
cat /sys/module/usbscope_iso/parameters/frame_status > /out/cancel-status.txt
cat /sys/module/usbscope_iso/parameters/edge_status > /out/edge-status.txt
cat /sys/module/usbscope_iso/parameters/edge_lengths > /out/edge-lengths.txt
cat /sys/module/usbscope_iso/parameters/short_data > /out/short-data.txt
wait $capture || fail
/usbscope -r /out/edges.usbraw -w /out/edges-replay.pcapng --fail-on-loss || fail
cmp /out/edges.pcapng /out/edges-replay.pcapng || fail
/usbscope -r /out/edges.pcapng -w /out/edges-roundtrip.pcapng --fail-on-loss || fail
cmp /out/edges.pcapng /out/edges-roundtrip.pcapng || fail
echo USBSCOPE_EDGE_GUEST_PASS
sync
echo USBSCOPE_VM_PASS'''))
    if args.compare_tcpdump:
        script = init.read_text().replace("'^# CONFIG_USB_MON is not set$'", "'^CONFIG_USB_MON=y$'")
        script = script.replace('/usbscope --bpf-object /usbscope.bpf.o -w /out/live.pcapng', '''
test -c /dev/usbmon0 || fail
/tcpdump --version > /out/tcpdump-version.txt
# The shell opens the output before tcpdump drops to the guest-only account.
/tcpdump -i usbmon0 -s 0 -U -n -Z capture -w - > /out/tcpdump.pcap 2>/out/tcpdump.log &
reference=$!
for i in $(seq 1 600); do
    grep -q 'listening on usbmon0' /out/tcpdump.log && break
    kill -0 $reference 2>/dev/null || fail
    sleep 0.1
done
grep -q 'listening on usbmon0' /out/tcpdump.log || fail
/usbscope --bpf-object /usbscope.bpf.o -w /out/live.pcapng''', 1)
        script = script.replace('wait $capture || fail', '''wait $capture || fail
kill -INT $reference || fail
wait $reference || fail''', 1)
        init.write_text(script)
    init.chmod(0o755)
    # newc archive, generated without root or device nodes (devtmpfs supplies those).
    archive = work / 'initramfs.cpio'
    names = subprocess.run(['find', '.', '-print0'], cwd=tree, capture_output=True, check=True)
    with archive.open('wb') as output:
        subprocess.run(['cpio', '--null', '-o', '--format=newc', '--owner=0:0'], cwd=tree,
                       input=names.stdout, stdout=output, stderr=subprocess.PIPE, check=True)
    disk = work / 'disk.raw'
    with disk.open('wb') as f:
        f.truncate(16 * 1024 * 1024)
    machine = ['-machine', 'virt,gic-version=3', '-cpu', 'max'] if arm64 else []
    console = 'ttyAMA0' if arm64 else 'ttyS0'
    qemu_arch = 'aarch64' if arm64 else 'x86_64'
    command = [f'qemu-system-{qemu_arch}', *machine, '-accel', 'tcg', '-m', '512', '-smp', '2',
        '-kernel', str(args.kernel.resolve()), '-initrd', str(archive),
        '-append', f'console={console} panic=-1', '-nographic', '-no-reboot',
        '-monitor', 'none', '-nic', 'none', '-device', 'qemu-xhci,id=xhci',
        '-drive', f'if=none,id=stick,format=raw,file={disk}',
        '-device', 'usb-storage,bus=xhci.0,drive=stick,port=1']
    if args.live:
        command += ['-virtfs', f'local,path={args.artifacts.resolve()},mount_tag=artifacts,security_model=mapped-xattr']
    if args.audio:
        command += ['-audiodev', 'driver=none,id=audio', '-device', 'usb-audio,bus=xhci.0,port=2,audiodev=audio']
    log_path = args.log.resolve()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    print('Running QEMU; guest log:', log_path, flush=True)
    with log_path.open('w') as log:
        try:
            run = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=args.timeout)
        except subprocess.TimeoutExpired:
            raise SystemExit('VM timeout; see ' + str(log_path))
    text = log_path.read_text(errors='replace')
    if run.returncode or 'USBSCOPE_VM_PASS' not in text or 'USBSCOPE_VM_FAIL' in text:
        print(text[-12000:])
        raise SystemExit('VM e2e failed')
    if args.sg and '2 SG data events' not in text:
        raise SystemExit('SG e2e did not exercise both kernel SG data paths')
    print('\n'.join(line for line in text.splitlines() if 'OBSERVED' in line or 'USBSCOPE_' in line))
    if args.live:
        subprocess.run(['python3', str(ROOT / 'tests/vm/validate.py'), str(args.artifacts)]
                       + ['--binary', str(args.host_binary)]
                       + (['--audio'] if args.audio else []) + (['--filters'] if args.filters else []), cwd=ROOT, check=True)
    if args.compare_tcpdump:
        subprocess.run(['python3', str(ROOT / 'tests/vm/compare.py'), str(args.artifacts)]
                       + (['--audio'] if args.audio else []), cwd=ROOT, check=True)
        subprocess.run(['python3', str(ROOT / 'tests/vm/test_compare.py'), str(args.artifacts)], cwd=ROOT, check=True)
    if args.audio:
        subprocess.run(['python3', str(ROOT / 'tests/vm/validate_edges.py'), str(args.artifacts)],
                       cwd=ROOT, check=True)
