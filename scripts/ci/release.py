#!/usr/bin/env python3
"""Verify the installed release without requiring a target runtime or ELF tools."""
import argparse
import hashlib
import json
from pathlib import Path
import struct


TARGETS = {'x86_64': (62, 1), 'aarch64': (183, 1), 'aarch64_be': (183, 2)}


def require(condition, message):
    if not condition:
        raise ValueError(message)


class Elf:
    def __init__(self, path, machine, encoding):
        self.data = path.read_bytes()
        require(self.data[:6] == b'\x7fELF\x02' + bytes([encoding]),
                f'{path}: expected ELF64 with matching byte order')
        self.order = '<' if encoding == 1 else '>'
        (self.kind, actual_machine, _, _, self.phoff, self.shoff, _, _,
         self.phsize, self.phnum, self.shsize, self.shnum, self.strings) = self.unpack('HHIQQQIHHHHHH', 16)
        require(actual_machine == machine, f'{path}: ELF machine does not match {machine}')

    def unpack(self, layout, offset):
        return struct.unpack_from(self.order + layout, self.data, offset)

    def section(self, name):
        require(self.shsize == 64 and self.strings < self.shnum, 'invalid ELF section table')
        headers = [self.unpack('IIQQQQIIQQ', self.shoff + i * self.shsize)
                   for i in range(self.shnum)]
        table = headers[self.strings]
        names = self.data[table[4]:table[4] + table[5]]
        for header in headers:
            if names[header[0]:].split(b'\0', 1)[0] == name.encode():
                return self.data[header[4]:header[4] + header[5]]
        raise ValueError(f'missing ELF section: {name}')

    def check_static(self, arm64):
        require(self.kind in (2, 3) and self.phsize == 56 and self.phnum > 0,
                'expected an executable ELF with program headers')
        loads = 0
        for i in range(self.phnum):
            kind, _, offset, address, _, size, _, alignment = self.unpack(
                'IIQQQQQQ', self.phoff + i * self.phsize)
            require(kind != 3, 'release has a PT_INTERP dynamic loader')
            if kind == 2:
                for entry in range(offset, offset + size, 16):
                    tag, _ = self.unpack('qQ', entry)
                    require(tag != 1, 'release has a DT_NEEDED shared-library dependency')
                    if tag == 0:
                        break
            if kind == 1:
                loads += 1
                if arm64:
                    require(alignment >= 65536 and (address - offset) % 65536 == 0,
                            'ARM release must support 64 KiB page alignment')
        require(loads > 0, 'executable has no loadable segments')


def verify(arch, directory):
    machine, encoding = TARGETS[arch]
    directory = Path(directory)
    checksums = {}
    for line in (directory / 'SHA256SUMS').read_text().splitlines():
        digest, name = line.split()
        require(name in ('usbscope', 'usbscope.bpf.o') and name not in checksums,
                f'unexpected checksum entry: {name}')
        checksums[name] = digest
        require(hashlib.sha256((directory / name).read_bytes()).hexdigest() == digest,
                f'checksum mismatch: {name}')
    require(set(checksums) == {'usbscope', 'usbscope.bpf.o'}, 'incomplete checksums')
    binary = directory / 'usbscope'
    require(binary.stat().st_mode & 0o100, 'release executable mode was lost')
    Elf(binary, machine, encoding).check_static(arm64=machine == 183)
    bpf = Elf(directory / 'usbscope.bpf.o', 247, encoding)
    require(bpf.kind == 1, 'expected a relocatable BPF object')
    info = bpf.section('.usbscope')
    require(len(info) == 16 and info[:8] == b'USBSBPF1', 'invalid BPF build metadata')
    require(struct.unpack_from('<I', info, 8)[0] == machine, 'BPF target architecture mismatch')
    require(bpf.section('.BTF'), 'missing BPF BTF data')
    extension = bpf.section('.BTF.ext')
    require(len(extension) >= 32, 'missing BPF CO-RE metadata')
    header_size = struct.unpack_from(bpf.order + 'I', extension, 4)[0]
    core_offset, core_size = struct.unpack_from(bpf.order + 'II', extension, 24)
    require(core_size > 0 and header_size + core_offset + core_size <= len(extension),
            'missing BPF CO-RE relocations')
    for name in ('README.md', 'README.zh-CN.md', 'LICENSE-MIT', 'LICENSE-APACHE'):
        require((directory / name).is_file(), f'missing package file: {name}')
    return {'arch': arch, 'static': True, 'co_re': True, 'sha256': checksums}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('arch', choices=TARGETS)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.arch, args.directory), indent=2))
