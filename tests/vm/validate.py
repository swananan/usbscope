#!/usr/bin/env python3
"""Independent checks on real kernel capture, including exact USB payload bytes."""
from pathlib import Path
import re
import json
import struct
import subprocess
import sys

root = Path(sys.argv[1])
blob = (root / 'live.pcapng').read_bytes()
packets = []
offset = 0
while offset < len(blob):
    kind, size = struct.unpack_from('<II', blob, offset)
    assert size >= 12 and size % 4 == 0
    assert struct.unpack_from('<I', blob, offset + size - 4)[0] == size
    if kind == 6:
        caplen, origlen = struct.unpack_from('<II', blob, offset + 20)
        assert caplen == origlen
        packets.append(blob[offset + 28:offset + 28 + caplen])
    offset += size
assert offset == len(blob)
assert packets, 'no USB packets captured'
assert len({p[:8] for p in packets}) * 2 == len(packets), 'submission IDs were reused'
expected = (root / 'bulk.bin').read_bytes()
assert len(expected) == 2 * 1024 * 1024 + 512
for event, direction in [(ord('S'), 0), (ord('C'), 0x80)]:
    matches = [p for p in packets if p[8] == event and p[9] == 3
               and p[10] & 0x80 == direction and len(p) == len(expected) + 64]
    assert len(matches) == 1, (chr(event), 'missing or duplicate large URB', len(matches))
    assert matches[0][64:] == expected, 'captured USB payload differs from usbfs data'
    urb_id = matches[0][:8]
    pair = [p for p in packets if p[:8] == urb_id]
    assert sorted(p[8] for p in pair) == [ord('C'), ord('S')], 'URB pairing failed'
    assert next(p for p in pair if p[8] == ord('C'))[28:32] == bytes(4), 'completion status incorrect'
descriptor = (root / 'descriptor.bin').read_bytes()
assert any(p[8] == ord('C') and p[9] == 2 and p[64:] == descriptor for p in packets)
if '--audio' in sys.argv:
    actual_lengths = [int(x) for x in (root / 'iso-lengths.txt').read_text().strip().split(',')]
    frame_status = [int(x) for x in (root / 'iso-status.txt').read_text().strip().split(',')]
    assert len(actual_lengths) == len(frame_status) == 137
    context = json.loads((root / 'devices.json').read_text())
    assert any(d['product'] == 'QEMU USB Audio' and d['descriptors_hex'] for d in context['devices'])
    iso = [p for p in packets if p[9] == 0]
    assert len(iso) == 2, 'missing ISO submission/completion'
    submitted = next(p for p in iso if p[8] == ord('S'))
    completed = next(p for p in iso if p[8] == ord('C'))
    assert submitted[:8] == completed[:8]
    assert struct.unpack_from('<I', submitted, 60)[0] == 137
    assert struct.unpack_from('<I', completed, 60)[0] == 137
    expected_iso = bytearray(136 * 224 + 192)
    for i in range(137):
        length = 192 if i % 3 else 188
        offset, captured_len = struct.unpack_from('<II', submitted, 64 + i * 16 + 4)
        assert (offset, captured_len) == (i * 224, length)
        status, offset, captured_len = struct.unpack_from('<iII', completed, 64 + i * 16)
        assert (status, offset, captured_len) == (frame_status[i], i * 224, actual_lengths[i])
        expected_iso[i * 224:i * 224 + length] = bytes((i * 13 + j * 7) % 251 for j in range(length))
    assert submitted[64 + 137 * 16:] == expected_iso, 'ISO offsets, gaps, or payload differ'
    assert len(completed) == 64 + 137 * 16, 'OUT completion must not duplicate payload'
    decoded_iso = subprocess.run(['tshark', '-r', str(root / 'live.pcapng'), '-Y', 'usb.transfer_type == 0',
        '-T', 'fields', '-e', 'usb.iso.numdesc', '-e', 'usb.iso.iso_off'],
        capture_output=True, text=True, check=True).stdout.strip().splitlines()
    assert len(decoded_iso) == 2
    for line in decoded_iso:
        count, offsets = line.split('\t')
        assert all(int(n) == 137 for n in count.split(',')) and len(offsets.split(',')) == 137
    print('ISO_E2E_PASS: 137 audio frames, per-frame status/length, original offsets and zero-filled gaps')
replay = root / 'replay.pcapng'
subprocess.run(['target/debug/usbscope', '-r', str(root / 'live.usbraw'), '-w', str(replay), '--fail-on-loss'], check=True)
assert replay.read_bytes() == blob, 'raw replay changed captured packets'
parsed = subprocess.run(['tshark', '-r', str(root / 'live.pcapng'), '-T', 'fields',
                         '-e', 'usb.urb_id', '-e', 'usb.urb_type', '-e', 'usb.data_len'],
                        capture_output=True, text=True, check=True)
assert len(parsed.stdout.splitlines()) == len(packets), 'TShark did not parse all events'
assert str(len(expected)) in parsed.stdout, 'TShark lost the large USB payload'
losses = (root / 'loss.log').read_text()
assert re.search(r'[1-9][0-9]* ring losses', losses), 'tiny ring did not report loss'
if '--filters' in sys.argv:
    filtered = subprocess.run(['tshark', '-r', str(root / 'filtered.pcapng'), '-T', 'fields',
        '-e', 'usb.urb_type', '-e', 'usb.urb_len'], capture_output=True, text=True, check=True).stdout.strip().splitlines()
    assert filtered == [f"'C'\t{len(expected)}"] * 2, filtered
    assert 'kernel: 2 submitted, 2 completed' in (root / 'filtered.log').read_text()
    mixed = subprocess.run(['tshark', '-r', str(root / 'mixed.pcapng'), '-T', 'fields', '-e', 'usb.urb_type'],
        capture_output=True, text=True, check=True).stdout.strip().splitlines()
    assert mixed == ["'S'"] * 3, mixed
    assert 'kernel: 9 submitted, 9 completed' in (root / 'mixed.log').read_text()
    print('FILTER_E2E_PASS: kernel rejection, completion latency, mixed OR without false negatives')
print(f'LIVE_E2E_PASS: {len(packets)} events, {len(expected)} bytes each direction, exact replay and TShark')
