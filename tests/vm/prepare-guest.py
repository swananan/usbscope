#!/usr/bin/env python3
"""Download an isolated Ubuntu 24.04 guest userspace; never install host packages."""
import argparse
import getpass
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--arch', choices=['x86_64', 'aarch64'], required=True)
parser.add_argument('--output', type=Path)
args = parser.parse_args()
root = (args.output or ROOT / 'target/vm-guest' / args.arch).resolve()
state = root / '.apt'
keyring = Path('/usr/share/keyrings/ubuntu-archive-keyring.gpg')
if not keyring.is_file():
    parser.error('install ubuntu-keyring first (Ubuntu archive signing keys are required)')
for directory in ('state/lists/partial', 'cache/archives/partial', 'log', 'empty'):
    (state / directory).mkdir(parents=True, exist_ok=True)
(state / 'status').touch()
architecture = 'arm64' if args.arch == 'aarch64' else 'amd64'
mirror = ('https://ports.ubuntu.com/ubuntu-ports' if architecture == 'arm64'
          else 'https://archive.ubuntu.com/ubuntu')
(state / 'sources.list').write_text(
    f'deb [arch={architecture} signed-by={keyring}] {mirror} noble main\n')
options = {
    'Dir::State': str(state / 'state'),
    'Dir::State::status': str(state / 'status'),
    'Dir::Cache': str(state / 'cache'),
    'Dir::Log': str(state / 'log'),
    'Dir::Etc::sourcelist': str(state / 'sources.list'),
    'Dir::Etc::sourceparts': str(state / 'empty'),
    'Dir::Etc::parts': str(state / 'empty'),
    'Dir::Etc::main': '/dev/null',
    'APT::Architecture': architecture,
    'APT::Sandbox::User': getpass.getuser(),
    'Acquire::Languages': 'none',
}
config = state / 'apt.conf'
config.write_text(''.join(f'{key} {json.dumps(value)};\n' for key, value in options.items())
                  + f'APT::Architectures {{ "{architecture}"; }};\n')
environment = dict(os.environ, APT_CONFIG=str(config))
subprocess.run(['apt-get', 'update'], env=environment, check=True)
subprocess.run(['apt-get', '--download-only', '--no-install-recommends', '-y',
                'install', 'busybox-static', 'tcpdump', 'libgcc-s1'],
               env=environment, check=True)
for package in sorted((state / 'cache/archives').glob('*.deb')):
    subprocess.run(['dpkg-deb', '--extract', str(package), str(root)], check=True)
print('Guest userspace:', root)
