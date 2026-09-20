#!/usr/bin/env python3
"""Rootless QEMU e2e; optionally compare live capture with tcpdump/usbmon."""
import argparse
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile

from guest import Guest

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser()
parser.add_argument('--arch', choices=['x86_64', 'aarch64'], default=platform.machine())
parser.add_argument('--kernel', type=Path)
parser.add_argument('--bpf-object', type=Path)
parser.add_argument('--guest-root', type=Path,
                    help='guest userspace from prepare-guest.py; required for cross-architecture runs')
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
    parser.error('cross-architecture runs require --guest-root (see prepare-guest.py)')
kernel_arch = 'arm64' if args.arch == 'aarch64' else 'x86'
image = 'Image' if args.arch == 'aarch64' else 'bzImage'
kernel_dir = 'vm-kernel-aarch64' if args.arch == 'aarch64' else 'vm-kernel'
args.kernel = args.kernel or ROOT / f'target/{kernel_dir}/arch/{kernel_arch}/boot/{image}'
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
compiler = f'{args.arch}-linux-gnu-gcc' if cross else 'gcc'
module_flags = [f'ARCH={kernel_arch}']
if cross:
    build_environment.setdefault(f'CARGO_TARGET_{target.upper().replace("-", "_")}_LINKER', compiler)
    module_flags += [f'CROSS_COMPILE={args.arch}-linux-gnu-']
subprocess.run(['cargo', 'build', '--locked', '--example', 'probe-smoke'] + guest_flags,
               cwd=ROOT, env=build_environment, check=True)
if args.live:
    subprocess.run(['cargo', 'build', '--locked'] + guest_flags, cwd=ROOT, env=build_environment, check=True)
    # Offline validation runs on the host, even when capture runs on another CPU.
    subprocess.run(['cargo', 'build', '--locked'] + build_flags, cwd=ROOT, check=True)
    args.artifacts.mkdir(parents=True, exist_ok=True)
fixture = ROOT / f'target/{args.arch}/usb-fixture'
fixture.parent.mkdir(parents=True, exist_ok=True)
subprocess.run([compiler, '-O2', '-Wall', '-Werror', '-o', str(fixture),
                str(ROOT / 'tests/vm/usb-fixture.c')], check=True)

with tempfile.TemporaryDirectory(prefix='usbscope-vm-', dir=ROOT / 'target') as temp:
    work = Path(temp)
    if args.audio:
        module_dir = work / 'module'
        shutil.copytree(ROOT / 'tests/vm/kernel', module_dir)
        kernel_build = args.kernel.resolve().parents[3]
        subprocess.run(['make', '-s', '-C', str(kernel_build), '-j4', *module_flags, 'modules'], check=True)
        subprocess.run(['make', '-s', '-C', str(kernel_build), *module_flags, f'M={module_dir}', 'modules'], check=True)
    tree = work / 'root'
    tree.mkdir()
    for directory in ['bin', 'dev', 'proc', 'sys', 'tmp', 'run', 'out']:
        (tree / directory).mkdir()

    guest = Guest(tree, args.guest_root or Path('/'), args.arch)
    guest.binary(guest.find('busybox'), '/bin/busybox')
    guest.binary(guest_build / 'examples/probe-smoke', '/probe-smoke')
    guest.binary(fixture, '/usb-fixture')
    if args.live:
        guest.binary(guest_build / 'usbscope', '/usbscope')
    if args.compare_tcpdump:
        guest.binary(guest.find('tcpdump'), '/tcpdump')
        (tree / 'etc').mkdir()
        (tree / 'etc/passwd').write_text('root:x:0:0:root:/root:/bin/sh\ncapture:x:65534:65534:capture:/tmp:/bin/sh\n')
        (tree / 'etc/group').write_text('root:x:0:\ncapture:x:65534:\n')
        (tree / 'etc/nsswitch.conf').write_text('passwd: files\ngroup: files\n')
    guest.install(args.bpf_object, '/usbscope.bpf.o')
    if args.audio:
        guest.install(module_dir / 'usbscope_iso.ko', '/usbscope_iso.ko')
    init = tree / 'init'
    init.write_text('''#!/bin/busybox sh
/bin/busybox --install -s /bin
export LC_ALL=C
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
fail() { echo USBSCOPE_VM_FAIL; reboot -f; }
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
    if args.live:
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
    machine = ['-machine', 'virt,gic-version=3', '-cpu', 'max'] if args.arch == 'aarch64' else []
    console = 'ttyAMA0' if args.arch == 'aarch64' else 'ttyS0'
    command = [f'qemu-system-{args.arch}', *machine, '-accel', 'tcg', '-m', '512', '-smp', '2',
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
                       + ['--binary', str(ROOT / f'target/{profile}/usbscope')]
                       + (['--audio'] if args.audio else []) + (['--filters'] if args.filters else []), cwd=ROOT, check=True)
    if args.compare_tcpdump:
        subprocess.run(['python3', str(ROOT / 'tests/vm/compare.py'), str(args.artifacts)]
                       + (['--audio'] if args.audio else []), cwd=ROOT, check=True)
        subprocess.run(['python3', str(ROOT / 'tests/vm/test_compare.py'), str(args.artifacts)], cwd=ROOT, check=True)
