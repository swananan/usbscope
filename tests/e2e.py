#!/usr/bin/env python3
"""Independent binary fixtures -> real CLI -> independent pcapng/TShark checks."""
import argparse
import itertools
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

PARSER = argparse.ArgumentParser()
PARSER.add_argument('--binary', default='target/debug/usbscope')
PARSER.add_argument('--require-tshark', action='store_true')
ARGS, REST = PARSER.parse_known_args()
BINARY = str(Path(ARGS.binary).resolve())
TSHARK = shutil.which('tshark')
if ARGS.require_tshark and not TSHARK:
    PARSER.error('tshark is required for this e2e run')


def record(kind, event_id, body=b'', offset=0):
    data = struct.pack('<HHIQQ', 1, kind, 24 + len(body), event_id, offset) + body
    return struct.pack('<I', len(data)) + data


def meta(urb=1, event='S', transfer=3, endpoint=2, length=0, actual=0,
         payload=0, descriptors=0, status=-115, setup=None):
    result = struct.pack('<QQHBBBBBBiIIIiiIIiHH8s',
        urb, 1700000000123456000, 1, 5, endpoint, transfer, ord(event),
        int(setup is not None), int(payload != 0), status, length, actual,
        payload, 1 if transfer == 0 else 0, 100, 0, descriptors, 0,
        0x1234, 0x5678, setup or bytes(8))
    assert len(result) == 72
    return result


def end(event_id, copied=0, descriptors=0, reason=0):
    return record(4, event_id, struct.pack('<QII', copied, descriptors, reason))


def packets(blob):
    result = []
    offset = 0
    while offset < len(blob):
        kind, size = struct.unpack_from('<II', blob, offset)
        assert size >= 12 and size % 4 == 0
        assert struct.unpack_from('<I', blob, offset + size - 4)[0] == size
        if kind == 1:
            assert struct.unpack_from('<HHI', blob, offset + 8) == (220, 0, 0)
        if kind == 6:
            caplen, origlen = struct.unpack_from('<II', blob, offset + 20)
            assert caplen == origlen
            result.append(blob[offset + 28:offset + 28 + caplen])
        offset += size
    assert offset == len(blob)
    return result


class CaptureE2E(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='usbscope-e2e-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def convert(self, records, success=True, strict=True, stdout=False):
        source = self.root / 'input.usbraw'
        source.write_bytes(b'USBSCP\0\x01' + b''.join(records))
        target = self.root / 'output.pcapng'
        command = [BINARY, '-r', str(source), '-w', '-' if stdout else str(target)]
        if strict:
            command.append('--fail-on-loss')
        run = subprocess.run(command, capture_output=True, timeout=30)
        self.assertEqual(run.returncode == 0, success, run.stderr.decode())
        if stdout:
            target.write_bytes(run.stdout)
        return target, run

    def tshark(self, target, *fields):
        if not TSHARK:
            self.skipTest('TShark not installed; use --require-tshark in CI')
        command = [TSHARK, '-r', str(target), '-T', 'fields']
        command += list(itertools.chain.from_iterable(('-e', f) for f in fields))
        run = subprocess.run(command, capture_output=True, text=True, timeout=30)
        self.assertEqual(run.returncode, 0, run.stderr)
        return run.stdout.strip().splitlines()

    def test_large_payload_and_interleaved_events(self):
        # Exceeds both conventional snaplen and the in-memory spool threshold.
        payload = bytes(range(256)) * 8192 + b'tail'
        records = [record(1, 1, meta(length=len(payload), payload=len(payload))),
                   record(1, 2, meta(urb=2, event='C', endpoint=0x81, length=3,
                                     actual=3, payload=3, status=0)),
                   record(2, 2, b'abc')]
        # Fragment order must not affect reconstruction.
        offsets = list(range(0, len(payload), 16384))
        for offset in reversed(offsets):
            records.append(record(2, 1, payload[offset:offset + 16384], offset))
        records += [end(1, len(payload)), end(2, 3)]
        target, _ = self.convert(records)
        decoded = packets(target.read_bytes())
        self.assertEqual(decoded[0][64:], payload)
        self.assertEqual(decoded[1][64:], b'abc')
        self.assertEqual(self.tshark(target, 'usb.urb_len', 'usb.data_len'),
                         [f'{len(payload)}\t{len(payload)}', '3\t3'])

    def test_iso_sparse_payload_and_more_than_128_descriptors(self):
        count = 137
        span = (count - 1) * 1024 + 4
        records = [record(1, 1, meta(event='C', transfer=0, endpoint=0x81,
                   length=count * 1024, actual=count * 4, payload=span,
                   descriptors=count, status=0))]
        for i in range(count):
            records += [record(3, 1, struct.pack('<iIII', 0, i * 1024, 4, 0), i),
                        record(2, 1, struct.pack('<I', i), i * 1024)]
        records.append(end(1, count * 4, count))
        target, _ = self.convert(records)
        packet = packets(target.read_bytes())[0]
        data = packet[64 + 16 * count:]
        self.assertEqual(len(data), span)
        for i in range(count):
            self.assertEqual(data[i * 1024:i * 1024 + 4], struct.pack('<I', i))
        self.assertEqual(data[4:1024], bytes(1020))
        rows = self.tshark(target, 'usb.iso.numdesc', 'usb.iso.data')
        self.assertTrue(rows[0].startswith('137,137\t'), rows)
        self.assertEqual(len(rows[0].split('\t')[1].split(',')), count)

    def test_control_setup_and_binary_stdout(self):
        setup = struct.pack('<BBHHH', 0x80, 6, 0x0100, 0, 18)
        target, run = self.convert([record(1, 1, meta(transfer=2, endpoint=0x80,
                                   length=18, setup=setup)), end(1)], stdout=True)
        self.assertTrue(run.stdout.startswith(b'\x0a\x0d\x0d\x0a'))
        self.assertIn(b'1 events written', run.stderr)
        self.assertEqual(packets(target.read_bytes())[0][40:48], setup)
        self.assertEqual(self.tshark(target, 'usb.setup.bRequest'), ['6'])

    def test_missing_payload_is_loss_not_a_complete_packet(self):
        target, run = self.convert([record(1, 1, meta(length=6, payload=6)),
                                   record(2, 1, b'abc'), end(1, 3)], success=False)
        self.assertIn(b'1 incomplete events', run.stderr)
        self.assertEqual(packets(target.read_bytes()), [])

    def test_missing_end_and_orphan_are_reported(self):
        _, run = self.convert([record(1, 1, meta()), end(2)], success=False)
        self.assertIn(b'1 incomplete events; 1 orphan records', run.stderr)

    def test_kernel_abort_is_reported(self):
        target, run = self.convert([record(1, 1, meta()), end(1, reason=2)], success=False)
        self.assertIn(b'1 incomplete events', run.stderr)
        self.assertEqual(packets(target.read_bytes()), [])

    def test_overlapping_fragments_are_rejected(self):
        _, run = self.convert([record(1, 1, meta(length=6, payload=6)),
                              record(2, 1, b'abcd'), record(2, 1, b'cdef', 2)], success=False)
        self.assertIn(b'overlapping', run.stderr)

    def test_truncated_archive_is_rejected(self):
        _, run = self.convert([record(1, 1, meta())[:-1]], success=False)
        self.assertIn(b'truncated archive', run.stderr)

    def test_untrusted_record_size_is_rejected(self):
        _, run = self.convert([struct.pack('<I', 0xffffffff)], success=False)
        self.assertIn(b'invalid archive record length', run.stderr)


if __name__ == '__main__':
    unittest.main(argv=['e2e.py'] + REST, verbosity=2)
