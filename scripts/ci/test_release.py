"""Release contracts: static PIE is allowed, runtime loaders/libraries are not."""
from pathlib import Path
import struct
import tempfile
import unittest

from release import Elf


class StaticReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'fixture'

    def fixture(self, arch, extra=None, alignment=65536):
        machine, encoding = (62, 1) if arch == 'x86_64' else (183, 2 if arch == 'aarch64_be' else 1)
        order = '<' if encoding == 1 else '>'
        data = bytearray(1024)
        data[:16] = b'\x7fELF' + bytes([2, encoding, 1]) + bytes(9)
        # ELF64 static PIE; optional PT_DYNAMIC or PT_INTERP follows PT_LOAD.
        struct.pack_into(order + 'HHIQQQIHHHHHH', data, 16,
                         3, machine, 1, 0, 64, 0, 0, 64, 56, 1 + (extra is not None), 0, 0, 0)
        struct.pack_into(order + 'IIQQQQQQ', data, 64, 1, 5, 0, 0, 0, 1024, 1024, alignment)
        if extra is not None:
            kind, dynamic_tag = extra
            struct.pack_into(order + 'IIQQQQQQ', data, 120, kind, 4, 512, 512, 512, 32, 32, 8)
            struct.pack_into(order + 'qQqQ', data, 512, dynamic_tag, 1, 0, 0)
        self.path.write_bytes(data)
        return Elf(self.path, machine, encoding)

    def test_static_pie_in_both_byte_orders(self):
        for arch in ('x86_64', 'aarch64', 'aarch64_be'):
            with self.subTest(arch=arch):
                # A static PIE may have PT_DYNAMIC, containing only relocations.
                self.fixture(arch, extra=(2, 7)).check_static(arm64=arch != 'x86_64')

    def test_dynamic_loader_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'PT_INTERP'):
            self.fixture('x86_64', extra=(3, 0)).check_static(arm64=False)

    def test_needed_library_without_interpreter_is_rejected(self):
        for arch in ('x86_64', 'aarch64_be'):
            with self.subTest(arch=arch), self.assertRaisesRegex(ValueError, 'DT_NEEDED'):
                self.fixture(arch, extra=(2, 1)).check_static(arm64=arch != 'x86_64')

    def test_arm_requires_64k_alignment(self):
        for arch in ('aarch64', 'aarch64_be'):
            with self.subTest(arch=arch), self.assertRaisesRegex(ValueError, '64 KiB'):
                self.fixture(arch, alignment=4096).check_static(arm64=True)


if __name__ == '__main__':
    unittest.main()
