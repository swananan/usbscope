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
         payload=0, descriptors=0, status=-115, setup=None, bus=1, device=5,
         timestamp=1700000000123456000):
    result = struct.pack('<QQHBBBBBBiIIIiiIIiHH8s',
        urb, timestamp, bus, device, endpoint, transfer, ord(event),
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

    def convert(self, records, success=True, strict=True, stdout=False, expression=None, options=()):
        source = self.root / 'input.usbraw'
        source.write_bytes(b'USBSCP\0\x01' + b''.join(records))
        target = self.root / 'output.pcapng'
        command = [BINARY, '-r', str(source), '-w', '-' if stdout else str(target)]
        if strict:
            command.append('--fail-on-loss')
        command += list(options)
        if expression is not None:
            command.append(expression)
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

    def test_filter_boolean_precedence_fields_and_masks(self):
        records = []
        for i, (bus, endpoint, transfer) in enumerate([(1, 2, 3), (2, 0x81, 1), (2, 0x82, 3)], 1):
            records += [record(1, i, meta(urb=i, bus=bus, endpoint=endpoint, transfer=transfer)), end(i)]
        for expression, ids in [
            ('bus 1 or in and interrupt', [1, 2]),
            ('(bus 1 or in) and bulk', [1, 3]),
            ('not (bus 1 or interrupt)', [3]),
            ('vid 0x1234 pid 0x5678 ep & 0x80 = 0x80 and epnum 2', [3]),
            ('requested >= 0 and not dev != 5 and type bulk', [1, 3]),
        ]:
            with self.subTest(expression=expression):
                target, _ = self.convert(records, expression=expression)
                self.assertEqual([struct.unpack_from('<Q', p)[0] for p in packets(target.read_bytes())], ids)

    def test_filter_setup_and_missing_fields_under_not(self):
        setup = bytes.fromhex('8006000100001200')
        records = [record(1, 1, meta(urb=1, transfer=2, endpoint=0x80, length=18, setup=setup)), end(1),
                   record(1, 2, meta(urb=1, event='C', transfer=2, endpoint=0x80, length=18, actual=18, payload=18, status=0)),
                   record(2, 2, bytes(18)), end(2, 18)]
        for expression, count in [('setup.request 6 and setup.value 0x100 and setup.length 18', 1),
                                  ('not setup.request 7', 1), ('not payload[99] = 0', 0),
                                  ('event complete and status 0 and actual 18', 1)]:
            target, _ = self.convert(records, expression=expression)
            self.assertEqual(len(packets(target.read_bytes())), count)

    def test_filter_payload_across_chunks_and_big_endian_slices(self):
        payload = b'x' * 16382 + b'USB-pattern' + bytes([0xfe, 0xdc, 0xba, 0x98])
        records = [record(1, 1, meta(length=len(payload), payload=len(payload)))]
        for offset in range(0, len(payload), 16384):
            records.append(record(2, 1, payload[offset:offset + 16384], offset))
        records.append(end(1, len(payload)))
        for expression in ['payload contains "USB-pattern"', 'payload contains 0x5553422d7061747465726e',
                           'payload[16382:4] = 0x5553422d', f'payload[{len(payload)-4}:4] & 0xffff0000 = 0xfedc0000']:
            target, _ = self.convert(records, expression=expression)
            self.assertEqual(packets(target.read_bytes())[0][64:], payload)

    def test_filter_latency_uses_unfiltered_submission(self):
        records = [record(1, 1, meta(urb=7, timestamp=1_000_000)), end(1),
                   record(1, 2, meta(urb=7, event='C', status=0, timestamp=4_000_000)), end(2)]
        target, _ = self.convert(records, expression='event complete and latency >= 2ms and latency < 4ms')
        self.assertEqual([p[8] for p in packets(target.read_bytes())], [ord('C')])
        target, _ = self.convert(records, expression='not latency < 1ms')
        self.assertEqual(len(packets(target.read_bytes())), 1)

    def test_filter_does_not_match_iso_padding(self):
        records = [record(1, 1, meta(event='C', transfer=0, endpoint=0x81, length=16,
                                   actual=4, payload=16, descriptors=2, status=0)),
                   record(3, 1, struct.pack('<iIII', 0, 0, 2, 0), 0),
                   record(3, 1, struct.pack('<iIII', 0, 14, 2, 0), 1),
                   record(2, 1, b'AB', 0), record(2, 1, b'CD', 14), end(1, 4, 2)]
        for expression, count in [('payload contains 0x0000', 0), ('payload[2] = 0', 0),
                                  ('not payload[2] = 0', 0), ('payload contains "CD"', 1)]:
            target, _ = self.convert(records, expression=expression)
            self.assertEqual(len(packets(target.read_bytes())), count)

    def test_filter_errors_and_explain_require_no_kernel_privileges(self):
        for expression in ['bus', 'payload[0:3] = 1', '(bulk', 'payload contains 0x1', 'vid 0xgg', 'nonsense 1']:
            result = subprocess.run([BINARY, '-d', expression], capture_output=True)
            self.assertNotEqual(result.returncode, 0, expression)
        for expression in ['bus 1 or payload contains "x"', 'not (bus 1 and status 0)']:
            result = subprocess.run([BINARY, '-d', expression], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertIn(b'Safe kernel prefilter: []', result.stdout)

    def test_pcapng_roundtrip_and_missing_identity(self):
        records = [record(1, 1, meta(urb=7, endpoint=0x81, length=9)), end(1),
                   record(1, 2, meta(urb=7, event='C', endpoint=0x81, length=9,
                                     actual=3, payload=3, status=0)), record(2, 2, b'abc'), end(2, 3)]
        source, _ = self.convert(records)
        target = self.root / 'roundtrip.pcapng'
        result = subprocess.run([BINARY, '-r', str(source), '-w', str(target), '--fail-on-loss'], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(source.read_bytes(), target.read_bytes())
        for expression, count in [('requested 9 and event complete', 1), ('actual 3', 1),
                                  ('vid 0x1234', 0), ('not pid 1', 0)]:
            result = subprocess.run([BINARY, '-r', str(source), '-w', str(target), expression], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(len(packets(target.read_bytes())), count)

    def test_pcapng_big_endian_nanoseconds_and_timestamp_offset(self):
        def block(kind, body):
            size = len(body) + 12
            return struct.pack('>II', kind, size) + body + struct.pack('>I', size)
        usb = bytearray(67)
        struct.pack_into('>Q', usb, 0, 77)
        usb[8:12] = bytes([ord('C'), 3, 0x81, 5])
        struct.pack_into('>H', usb, 12, 2)
        usb[14] = ord('-')
        struct.pack_into('>iII', usb, 28, 0, 3, 3)
        usb[64:] = b'abc'
        section = block(0x0a0d0d0a, struct.pack('>IHHq', 0x1a2b3c4d, 1, 0, -1))
        options = struct.pack('>HHB3x', 9, 1, 9) + struct.pack('>HHq', 14, 8, 2) + bytes(4)
        interface = block(1, struct.pack('>HHI', 220, 0, 0) + options)
        packet = block(6, struct.pack('>IIIII', 0, 0, 1_234_567_000, len(usb), len(usb)) + usb + bytes(1))
        source = self.root / 'big-endian.pcapng'
        source.write_bytes(section + interface + packet)
        target = self.root / 'converted.pcapng'
        result = subprocess.run([BINARY, '-r', str(source), '-w', str(target), '--fail-on-loss'], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        parsed = packets(target.read_bytes())
        self.assertEqual(parsed[0][64:], b'abc')
        self.assertEqual(struct.unpack_from('<Q', parsed[0], 0)[0], 77)
        self.assertEqual(self.tshark(target, 'frame.time_epoch'), ['3.234567000'])

    def test_pcapng_iso_without_submission_preserves_sparse_and_empty_frames(self):
        descriptors = [(0, 0, 2, 0), (0, 14, 2, 0), (0, 48, 0, 0)]
        for endpoint in [2, 0x82]:
            with self.subTest(endpoint=endpoint):
                incoming = endpoint & 0x80
                records = [record(1, 1, meta(event='C', transfer=0, endpoint=endpoint,
                    length=64, actual=4, payload=16 if incoming else 0,
                    descriptors=3, status=0))]
                records += [record(3, 1, struct.pack('<iIII', *d), i)
                            for i, d in enumerate(descriptors)]
                if incoming:
                    records += [record(2, 1, b'AB'), record(2, 1, b'CD', 14)]
                records.append(end(1, 4 if incoming else 0, 3))
                source, _ = self.convert(records)
                expected = source.read_bytes()
                target = self.root / 'iso-replayed.pcapng'
                result = subprocess.run([BINARY, '-r', str(source), '-w', str(target),
                    '--fail-on-loss', '--iso-stats'], capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.assertEqual(target.read_bytes(), expected)
                self.assertIn(b'3 frames, 4 bytes', result.stderr)
                self.assertIn(b'1 empty frames', result.stderr)
                self.assertEqual(self.tshark(target, 'usb.iso.iso_off'), ['0,14,48'])
                result = subprocess.run([BINARY, '-r', str(source), '-w', str(target),
                    'not requested 64'], capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.assertEqual(packets(target.read_bytes()), [], 'unknown requested length matched')

    def test_pcapng_iso_still_checks_a_known_submission_buffer(self):
        records = [record(1, 1, meta(urb=7, transfer=0, endpoint=0x82, length=64,
                                   descriptors=1)),
                   record(3, 1, struct.pack('<iIII', 0, 48, 2, 0)), end(1, descriptors=1),
                   record(1, 2, meta(urb=7, event='C', transfer=0, endpoint=0x82,
                                    length=64, actual=0, descriptors=1, status=0)),
                   record(3, 2, struct.pack('<iIII', 0, 48, 0, 0)), end(2, descriptors=1)]
        source, _ = self.convert(records)
        corrupt = bytearray(source.read_bytes())
        # Keep the submitted descriptor valid, but move the completion's empty
        # frame past the 64-byte buffer known from its matching submission.
        second = 48 + struct.unpack_from('<I', corrupt, 52)[0]
        struct.pack_into('<I', corrupt, second + 28 + 64 + 4, 65)
        source.write_bytes(corrupt)
        result = subprocess.run([BINARY, '-r', str(source)], capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'ISO descriptor outside URB buffer', result.stderr)

    def test_pcapng_malformed_lengths_and_snap_truncation(self):
        source, _ = self.convert([record(1, 1, meta(length=4, payload=4)), record(2, 1, b'abcd'), end(1, 4)])
        original = source.read_bytes()
        target = self.root / 'validated.pcapng'
        # EPB starts after the 28-byte SHB and 20-byte IDB.
        for at, value in [(48 + 20, 0xffffffff), (len(original) - 4, 0)]:
            corrupt = bytearray(original)
            struct.pack_into('<I', corrupt, at, value)
            source.write_bytes(corrupt)
            result = subprocess.run([BINARY, '-r', str(source), '-w', str(target)], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
        truncated = bytearray(original)
        struct.pack_into('<I', truncated, 48 + 24, 999)
        source.write_bytes(truncated)
        result = subprocess.run([BINARY, '-r', str(source), '-w', str(target), '--fail-on-loss'], capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'1 incomplete events', result.stderr)
        self.assertEqual(packets(target.read_bytes()), [])
        frame = packets(original)[0]
        body = struct.pack('<I', len(frame)) + frame
        body += bytes((-len(body)) % 4)
        size = len(body) + 12
        source.write_bytes(original[:48] + struct.pack('<II', 3, size) + body + struct.pack('<I', size))
        result = subprocess.run([BINARY, '-r', str(source), '-w', str(target)], capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'Enhanced Packet Blocks', result.stderr)

    def test_rotation_keeps_large_events_whole_and_stops_at_file_count(self):
        payload = b'z' * (2 * 1024 * 1024 + 3)
        records = []
        for event_id in [1, 2, 3]:
            records.append(record(1, event_id, meta(urb=event_id, length=len(payload), payload=len(payload))))
            for offset in range(0, len(payload), 16384):
                records.append(record(2, event_id, payload[offset:offset + 16384], offset))
            records.append(end(event_id, len(payload)))
        target, result = self.convert(records, options=['-C', '1', '-W', '2'])
        self.assertIn(b'2 events written', result.stderr)
        self.assertFalse(target.exists())
        files = sorted(self.root.glob('output.pcapng.*'))
        self.assertEqual(len(files), 2)
        for path in files:
            self.assertEqual(packets(path.read_bytes())[0][64:], payload)
            self.assertEqual(len(self.tshark(path, 'usb.data_len')), 1)

    def test_time_rotation_and_existing_files_are_protected(self):
        records = []
        for i, timestamp in enumerate([1_000_000_000, 1_500_000_000, 3_000_000_000], 1):
            records += [record(1, i, meta(urb=i, timestamp=timestamp)), end(i)]
        self.convert(records, options=['-G', '1'])
        files = sorted(self.root.glob('output.pcapng.*'))
        self.assertEqual([len(packets(p.read_bytes())) for p in files], [2, 1])
        before = files[0].read_bytes()
        self.convert(records, options=['-G', '1'], success=False)
        self.assertEqual(files[0].read_bytes(), before)

    def test_archive_preserves_loss_when_entire_events_are_missing(self):
        summary = record(5, 0, struct.pack('<8Q', 3, 3, 0, 2, 1, 0, 0, 0))
        target, result = self.convert([summary], success=False)
        self.assertIn(b'archive reports 3 kernel capture errors', result.stderr)
        self.assertEqual(packets(target.read_bytes()), [])

    def test_count_limit_does_not_report_intentionally_unread_fragments_as_loss(self):
        records = [record(1, 1, meta(urb=1, length=4, payload=4)),
                   record(1, 2, meta(urb=2)), end(2), record(2, 1, b'data'), end(1, 4)]
        target, result = self.convert(records, options=['-c', '1'])
        self.assertIn(b'0 incomplete events', result.stderr)
        self.assertEqual([struct.unpack_from('<Q', p)[0] for p in packets(target.read_bytes())], [2])

    def test_output_aliases_cannot_overwrite_input_or_bpf_object(self):
        source = self.root / 'source.usbraw'
        original = b'USBSCP\0\x01' + record(1, 1, meta()) + end(1)
        source.write_bytes(original)
        alias = self.root / 'alias.pcapng'
        alias.hardlink_to(source)
        result = subprocess.run([BINARY, '-r', str(source), '-w', str(alias)], capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(source.read_bytes(), original)
        obj = self.root / 'test.bpf.o'
        obj.write_bytes(b'object sentinel')
        result = subprocess.run([BINARY, '--bpf-object', str(obj), '-w', str(obj)], capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(obj.read_bytes(), b'object sentinel')
        self.convert([record(1, 1, meta()), end(1)], success=False,
            options=['-C', '1', '--raw-output', str(self.root / 'output.pcapng.000000')])
        self.assertTrue((self.root / 'output.pcapng.000000').read_bytes().startswith(bytes.fromhex('0a0d0d0a')))


if __name__ == '__main__':
    unittest.main(argv=['e2e.py'] + REST, verbosity=2)
