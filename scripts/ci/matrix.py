#!/usr/bin/env python3
"""Emit the pinned GitHub Actions kernel matrix; no network resolution in CI."""
import argparse
import json
from pathlib import Path
import re

MANIFEST = Path(__file__).with_name('kernels.json')
TARGETS = [('x86_64', '4K'), ('aarch64', '4K'), ('aarch64', '64K'),
           ('aarch64_be', '4K'), ('aarch64_be', '64K')]


def kernels(path=MANIFEST):
    entries = json.loads(path.read_text())['kernels']
    seen = set()
    for entry in entries:
        version = entry['version']
        if not re.fullmatch(r'[6-9]\.[0-9]+(?:\.[0-9]+)?', version):
            raise ValueError(f'invalid kernel version: {version}')
        if version in seen:
            raise ValueError(f'duplicate kernel version: {version}')
        seen.add(version)
        if not re.fullmatch(r'[0-9a-f]{64}', entry['sha256']):
            raise ValueError(f'invalid SHA-256 for {version}')
        if type(entry['pr']) is not bool:
            raise ValueError(f'pr must be a boolean for {version}')
        if type(entry.get('arm64_big_endian')) is not bool:
            raise ValueError(f'arm64_big_endian must be a boolean for {version}')
    if not entries or not any(k['pr'] for k in entries):
        raise ValueError('the full and PR matrices must not be empty')
    return entries


def matrix(profile):
    return {'include': [
        {'kernel': k['version'], 'sha256': k['sha256'], 'arch': arch,
         'pages': pages, 'usbmon': usbmon}
        for k in kernels() if profile == 'full' or k['pr']
        for arch, pages in TARGETS for usbmon in ('n', 'y')
        if arch != 'aarch64_be' or k['arm64_big_endian']
    ]}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=['pr', 'full'], default='pr')
    args = parser.parse_args()
    print(json.dumps(matrix(args.profile), separators=(',', ':')))
