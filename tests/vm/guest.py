"""Assemble native or cross-architecture guest binaries without executing them."""
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess


class Guest:
    def __init__(self, tree, sysroot, arch):
        self.tree = tree
        self.sysroot = sysroot.resolve()
        self.arch = arch
        self.installed = set()

    def find(self, name):
        if name.startswith('/'):
            candidates = [self.sysroot / name.lstrip('/'),
                          self.sysroot / 'usr' / name.lstrip('/')]
        else:
            candidates = [self.sysroot / directory / name for directory in (
                'bin', 'usr/bin', 'sbin', 'usr/sbin',
                f'lib/{self.arch}-linux-gnu', f'usr/lib/{self.arch}-linux-gnu',
                'lib', 'usr/lib')]
        for path in candidates:
            if path.is_file() and path.resolve().is_relative_to(self.sysroot):
                return path
        raise RuntimeError(f'{name} missing from guest userspace {self.sysroot}')

    def install(self, source, destination):
        destination = self.tree / str(destination).lstrip('/')
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)

    def binary(self, source, destination):
        source = Path(source)
        with source.open('rb') as stream:
            header = stream.read(20)
        machine = 183 if self.arch == 'aarch64' else 62
        if (header[:6] != b'\x7fELF\x02\x01' or len(header) != 20
                or struct.unpack_from('<H', header, 18)[0] != machine):
            raise RuntimeError(f'{source} is not a little-endian {self.arch} ELF binary')
        self.install(source, destination)
        if source.resolve() in self.installed:
            return
        self.installed.add(source.resolve())
        metadata = subprocess.run(['readelf', '--wide', '--program-headers', '--dynamic', str(source)],
                                  capture_output=True, text=True, check=True,
                                  env=dict(os.environ, LC_ALL='C')).stdout
        interpreter = re.search(r'Requesting program interpreter: ([^\]]+)', metadata)
        if interpreter:
            name = interpreter.group(1)
            self.binary(self.find(name), name)
        for name in re.findall(r'\(NEEDED\).*?\[([^\]]+)\]', metadata):
            self.binary(self.find(name), '/lib/' + name)
