#!/usr/bin/env python3
"""Build isolated arm64 big-endian VM tools from checksum-pinned sources."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
# Bootlin publishes the SDK digest; source digests also match Buildroot
# 2024.02 (libpcap) and 2025.02 (BusyBox/tcpdump).
SOURCES = {
    'toolchain': ('aarch64be--glibc--stable-2025.08-1.tar.xz',
                  '4eca1a03d3d73bd31427d0f231d40a9f00a682a50c6ae5b31f6738a4675f9dd8',
                  ['https://toolchains.bootlin.com/downloads/releases/toolchains/aarch64be/tarballs/']),
    'busybox': ('busybox-1.37.0.tar.bz2',
                '3311dff32e746499f4df0d5df04d7eb396382d7e108bb9250e7b519b837043a4',
                ['https://busybox.net/downloads/', 'https://sources.buildroot.net/busybox/']),
    # Match the LE baseline. 1.10.5 omits ISO descriptors from the original
    # length of data-bearing submissions, producing caplen > len.
    'libpcap': ('libpcap-1.10.4.tar.gz',
                'ed19a0383fad72e3ad435fd239d7cd80d64916b87269550159d20e47160ebe5f',
                ['https://www.tcpdump.org/release/', 'https://sources.buildroot.net/libpcap/']),
    'tcpdump': ('tcpdump-4.99.5.tar.gz',
                '8c75856e00addeeadf70dad67c9ff3dd368536b2b8563abf6854d7c764cd3adb',
                ['https://www.tcpdump.org/release/', 'https://sources.buildroot.net/tcpdump/']),
}


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(command, **kwargs):
    print(shlex.join(map(str, command)), flush=True)
    return subprocess.run(command, check=True, **kwargs)


def source(name, work):
    filename, expected, mirrors = SOURCES[name]
    archive = work / filename
    directory = work / ('toolchain' if name == 'toolchain' else filename.split('.tar.')[0])
    marker = directory / '.source-sha256'
    if marker.is_file() and marker.read_text().strip() == expected:
        return directory
    if not archive.is_file():
        partial = archive.with_suffix('.part')
        for mirror in mirrors:
            result = subprocess.run(['curl', '--fail', '--location', '--silent', '--show-error',
                                     '--retry', '3', '--connect-timeout', '20', '--max-time', '300',
                                     '--speed-time', '30', '--speed-limit', '1024',
                                     '--output', str(partial), mirror + filename])
            if result.returncode == 0:
                break
        else:
            raise RuntimeError(f'could not download {filename}')
        if digest(partial) != expected:
            raise ValueError(f'SHA-256 mismatch: {partial}')
        partial.replace(archive)
    if digest(archive) != expected:
        raise ValueError(f'SHA-256 mismatch: {archive}')
    directory.mkdir(parents=True, exist_ok=True)
    run(['tar', '-xf', archive, '-C', directory, '--strip-components=1'])
    marker.write_text(expected + '\n')
    return directory


def prepare(work, output, toolchain_only):
    work.mkdir(parents=True, exist_ok=True)
    sdk = source('toolchain', work)
    run([sdk / 'relocate-sdk.sh'])
    prefix = str(sdk / 'bin/aarch64_be-buildroot-linux-gnu-')
    (work / 'environment.sh').write_text(
        f'export PATH={shlex.quote(str(sdk / "bin"))}:"$PATH"\n'
        f'export CROSS_COMPILE={shlex.quote(prefix)}\n')
    if toolchain_only:
        return
    identity = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    marker = output / '.usbscope-be-tools.json'
    if marker.is_file() and json.loads(marker.read_text()).get('builder') == identity:
        print('Guest tools already built:', output)
        return
    env = dict(os.environ, CC=prefix + 'gcc', AR=prefix + 'ar', RANLIB=prefix + 'ranlib',
               STRIP=prefix + 'strip', PATH=str(sdk / 'bin') + os.pathsep + os.environ['PATH'])
    jobs = '-j' + os.environ.get('JOBS', '4')
    sysroot = Path(subprocess.check_output([prefix + 'gcc', '-print-sysroot'], text=True).strip())
    output.mkdir(parents=True, exist_ok=True)
    # Keep runtime libraries and their symlinks; headers and static SDK libraries
    # are unnecessary in the guest. No foreign executable runs on the host.
    for relative in ('lib', 'lib64', 'usr/lib', 'usr/lib64'):
        directory = sysroot / relative
        if directory.is_dir():
            for library in directory.rglob('*'):
                if library.suffix in ('.a', '.o'):
                    continue
                destination = output / relative / library.relative_to(directory)
                destination.parent.mkdir(parents=True, exist_ok=True)
                if library.is_symlink():
                    destination.unlink(missing_ok=True)
                    destination.symlink_to(os.readlink(library))
                elif library.is_dir():
                    destination.mkdir(exist_ok=True)
                else:
                    shutil.copy2(library, destination)
    busybox = source('busybox', work)
    build = work / 'busybox-build'
    build.mkdir(exist_ok=True)
    make = ['make', '-s', '-C', str(busybox), f'O={build}', 'ARCH=arm64', f'CROSS_COMPILE={prefix}',
            'EXTRA_LDFLAGS=-Wl,-z,max-page-size=65536']
    run(make + ['defconfig'], env=env)
    config = build / '.config'
    settings = {'STATIC': True, 'TC': False, 'USE_BB_CRYPT': True, 'USE_BB_CRYPT_SHA': True,
                'SHA1_HWACCEL': False, 'SHA256_HWACCEL': False}
    lines = config.read_text().splitlines()
    for key, enabled in settings.items():
        lines = [line for line in lines if not line.startswith(f'CONFIG_{key}=')
                 and line != f'# CONFIG_{key} is not set']
        lines.append(f'CONFIG_{key}=y' if enabled else f'# CONFIG_{key} is not set')
    config.write_text('\n'.join(lines) + '\n')
    run(make + ['oldconfig'], env=env, input=b'\n' * 100)
    run(make + [jobs], env=env)
    (output / 'bin').mkdir(exist_ok=True)
    shutil.copy2(build / 'busybox', output / 'bin/busybox')
    # Static 64 KiB-aligned tools run on both guest page sizes without the
    # SDK's 4 KiB-only loader. Explicit pkg-config paths exclude host libraries.
    install = work / 'pcap-install'
    env.update(PKG_CONFIG_LIBDIR=str(install / 'lib/pkgconfig'), PKG_CONFIG_SYSROOT_DIR='',
               CFLAGS='-O2', CPPFLAGS=f'-I{install}/include',
               LDFLAGS=f'-static -Wl,-z,max-page-size=65536 -L{install}/lib')
    for name, options in [
        ('libpcap', ['--disable-shared', '--without-libnl', '--disable-dbus',
                    '--disable-bluetooth', '--disable-rdma']),
        ('tcpdump', ['--without-crypto', '--with-user=capture']),
    ]:
        directory = source(name, work)
        run([directory / 'configure', '--host=aarch64_be-buildroot-linux-gnu',
             f'--prefix={install}', *options], cwd=directory, env=env)
        run(['make', '-s', jobs], cwd=directory, env=env)
        if name == 'libpcap':
            run(['make', '-s', 'install'], cwd=directory, env=env)
        else:
            shutil.copy2(directory / 'tcpdump', output / 'bin/tcpdump')
    marker.write_text(json.dumps({'builder': identity, 'sources': SOURCES}, indent=2) + '\n')
    print('Guest userspace:', output)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work-dir', type=Path, default=ROOT / 'target/be-tools')
    parser.add_argument('--output', type=Path, default=ROOT / 'target/vm-guest/aarch64_be')
    parser.add_argument('--toolchain-only', action='store_true')
    args = parser.parse_args()
    prepare(args.work_dir.resolve(), args.output.resolve(), args.toolchain_only)
