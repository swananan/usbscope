#!/usr/bin/env python3
"""Independent checks on real kernel capture, including exact USB payload bytes."""
from pathlib import Path
import re
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
print(f'LIVE_E2E_PASS: {len(packets)} events, {len(expected)} bytes each direction, exact replay and TShark')
