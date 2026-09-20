#!/usr/bin/env python3
"""Build or verify a compact, configuration-specific VM kernel cache."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from matrix import kernels

ROOT = Path(__file__).resolve().parents[2]


def sha256(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def verify_archive(path, expected):
    if sha256(path) != expected:
        raise ValueError(f'kernel source SHA-256 mismatch: {path}')


def source_tree(entry, work):
    version, digest = entry['version'], entry['sha256']
    archive = work / f'linux-{version}.tar.xz'
    source = work / f'linux-{version}'
    marker = source / '.usbscope-source-sha256'
    if marker.is_file() and marker.read_text().strip() == digest:
        return source
    if not archive.is_file():
        partial = archive.with_suffix('.part')
        for host in ('cdn.kernel.org', 'www.kernel.org'):
            url = f'https://{host}/pub/linux/kernel/v{version.split(".")[0]}.x/{archive.name}'
            print(f'Downloading {url}', flush=True)
            result = subprocess.run(['curl', '--silent', '--show-error', '--fail', '--location', '--retry', '3',
                                     '--connect-timeout', '20', '--max-time', '300', '--speed-time', '30',
                                     '--speed-limit', '1024', '--output', str(partial), url])
            if result.returncode == 0:
                break
        else:
            raise RuntimeError(f'could not download Linux {version} from kernel.org')
        verify_archive(partial, digest)
        partial.replace(archive)
    verify_archive(archive, digest)
    if source.exists():
        raise ValueError(f'unverified source directory already exists: {source}')
    # Extract only after verification, into a temporary directory on this filesystem.
    with tempfile.TemporaryDirectory(prefix='extract-', dir=work) as temp:
        subprocess.run(['tar', '-xf', str(archive), '-C', temp], check=True)
        (Path(temp) / source.name).rename(source)
    marker.write_text(digest + '\n')
    return source


def identity(args, entry):
    return {'version': args.version, 'source_sha256': entry['sha256'],
            'arch': args.arch, 'pages': args.pages, 'usbmon': args.usbmon}


def verify(bundle, expected):
    metadata = json.loads((bundle / 'metadata.json').read_text())
    for key, value in expected.items():
        if metadata[key] != value:
            raise ValueError(f'kernel cache {key}: expected {value}, found {metadata[key]}')
    release = expected['version'] + ('.0' if expected['version'].count('.') == 1 else '')
    if metadata['kernel_release'] != release:
        raise ValueError(f'kernel cache release: expected {release}, found {metadata["kernel_release"]}')
    if set(metadata['files']) != {'kernel', 'config', 'usbscope_iso.ko'}:
        raise ValueError('incomplete kernel cache file list')
    for name, digest in metadata['files'].items():
        if sha256(bundle / name) != digest:
            raise ValueError(f'kernel cache checksum mismatch: {name}')
    config = (bundle / 'config').read_text().splitlines()
    usbmon = 'CONFIG_USB_MON=y' if expected['usbmon'] == 'y' else '# CONFIG_USB_MON is not set'
    required = [usbmon, 'CONFIG_DEBUG_INFO_BTF=y', 'CONFIG_IKCONFIG_PROC=y']
    if expected['arch'] == 'aarch64':
        required += ['CONFIG_ARM64=y', f'CONFIG_ARM64_{expected["pages"]}_PAGES=y', 'CONFIG_ARM64_VA_BITS=48']
    else:
        required += ['CONFIG_X86_64=y']
    for setting in required:
        if setting not in config:
            raise ValueError(f'kernel cache config is missing: {setting}')
    return metadata


def build(args, entry):
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    source = source_tree(entry, work)
    output = work / f'build-{args.arch}-{args.pages}-usbmon-{args.usbmon}-{args.version}'
    arch = 'arm64' if args.arch == 'aarch64' else 'x86'
    env = dict(os.environ, ARCH=arch, ARM64_PAGE_SIZE=args.pages, USBMON=args.usbmon)
    subprocess.run([str(ROOT / 'tests/vm/build-kernel.sh'), str(source), str(output)], env=env, check=True)
    flags = [f'ARCH={arch}']
    if args.arch != os.uname().machine:
        flags += [f'CROSS_COMPILE={args.arch}-linux-gnu-']
    subprocess.run(['make', '-s', '-C', str(output), '-j' + os.environ.get('JOBS', '4'), *flags, 'modules'], check=True)
    with tempfile.TemporaryDirectory(prefix='iso-', dir=work) as temp:
        module = Path(temp)
        shutil.copytree(ROOT / 'tests/vm/kernel', module, dirs_exist_ok=True)
        subprocess.run(['make', '-s', '-C', str(output), *flags, f'M={module}', 'modules'], check=True)
        args.bundle.mkdir(parents=True, exist_ok=True)
        shutil.copy2(module / 'usbscope_iso.ko', args.bundle / 'usbscope_iso.ko')
    image = 'arch/arm64/boot/Image' if args.arch == 'aarch64' else 'arch/x86/boot/bzImage'
    shutil.copy2(output / image, args.bundle / 'kernel')
    shutil.copy2(output / '.config', args.bundle / 'config')
    metadata = identity(args, entry)
    metadata['kernel_release'] = (output / 'include/config/kernel.release').read_text().strip()
    metadata['files'] = {name: sha256(args.bundle / name) for name in ['kernel', 'config', 'usbscope_iso.ko']}
    (args.bundle / 'metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
    verify(args.bundle, identity(args, entry))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['build', 'verify'])
    parser.add_argument('--version', required=True)
    parser.add_argument('--arch', choices=['x86_64', 'aarch64'], required=True)
    parser.add_argument('--pages', choices=['4K', '64K'], required=True)
    parser.add_argument('--usbmon', choices=['n', 'y'], required=True)
    parser.add_argument('--bundle', type=Path, default=ROOT / 'target/ci/kernel')
    parser.add_argument('--work-dir', type=Path, default=ROOT / 'target/ci/kernel-work')
    args = parser.parse_args()
    if args.arch == 'x86_64' and args.pages != '4K':
        parser.error('x86_64 requires --pages 4K')
    entry = next((k for k in kernels() if k['version'] == args.version), None)
    if entry is None:
        parser.error('version is not pinned in scripts/ci/kernels.json')
    if args.command == 'build':
        build(args, entry)
    print(json.dumps(verify(args.bundle, identity(args, entry)), indent=2))
