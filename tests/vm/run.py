#!/usr/bin/env python3
"""Run USB eBPF tests in a rootless QEMU TCG guest with CONFIG_USB_MON=n."""
import argparse
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser()
parser.add_argument('--kernel', type=Path, default=ROOT / 'target/vm-kernel/arch/x86/boot/bzImage')
parser.add_argument('--timeout', type=int, default=120)
parser.add_argument('--log', type=Path, default=ROOT / 'target/vm-e2e.log')
args = parser.parse_args()
subprocess.run(['cargo', 'build', '--example', 'probe-smoke'], cwd=ROOT, check=True)
subprocess.run(['gcc', '-O2', '-Wall', '-Werror', '-o', str(ROOT / 'target/usb-fixture'),
                str(ROOT / 'tests/vm/usb-fixture.c')], check=True)

with tempfile.TemporaryDirectory(prefix='usbscope-vm-', dir=ROOT / 'target') as temp:
    work = Path(temp)
    tree = work / 'root'
    tree.mkdir()
    for directory in ['bin', 'dev', 'proc', 'sys', 'tmp', 'run']:
        (tree / directory).mkdir()

    def install(source, destination=None):
        source = Path(source)
        destination = tree / str(destination or source).lstrip('/')
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)

    def binary(source, destination):
        install(source, destination)
        deps = subprocess.run(['ldd', str(source)], capture_output=True, text=True)
        for line in deps.stdout.splitlines():
            match = re.search(r'(/\S+)', line)
            if match:
                install(match.group(1))

    binary(shutil.which('busybox'), '/bin/busybox')
    binary(ROOT / 'target/debug/examples/probe-smoke', '/probe-smoke')
    binary(ROOT / 'target/usb-fixture', '/usb-fixture')
    install(ROOT / 'target/usbscope.bpf.o', '/usbscope.bpf.o')
    init = tree / 'init'
    init.write_text('''#!/bin/busybox sh
/bin/busybox --install -s /bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
fail() { echo USBSCOPE_VM_FAIL; reboot -f; }
zcat /proc/config.gz | grep -q '^# CONFIG_USB_MON is not set$' || fail
test -r /sys/kernel/btf/vmlinux || fail
sleep 1
/probe-smoke /usbscope.bpf.o &
probe=$!
for i in $(seq 1 100); do
    test -f /tmp/probe-ready && break
    sleep 0.1
done
test -f /tmp/probe-ready || fail
/usb-fixture || fail
wait $probe || fail
cmp /tmp/probe-expected /tmp/probe-observed || fail
echo USBSCOPE_VM_PASS
reboot -f
''')
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
    command = ['qemu-system-x86_64', '-accel', 'tcg', '-m', '512', '-smp', '2',
        '-kernel', str(args.kernel.resolve()), '-initrd', str(archive),
        '-append', 'console=ttyS0 panic=-1 nokaslr', '-nographic', '-no-reboot',
        '-monitor', 'none', '-nic', 'none', '-device', 'qemu-xhci,id=xhci',
        '-drive', f'if=none,id=stick,format=raw,file={disk}',
        '-device', 'usb-storage,bus=xhci.0,drive=stick,port=1']
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
    print('\n'.join(line for line in text.splitlines() if 'OBSERVED' in line or 'USBSCOPE_' in line))
