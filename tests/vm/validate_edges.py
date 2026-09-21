#!/usr/bin/env python3
"""Check kernel-observed error paths against the fixture driver's own results."""
from pathlib import Path
import subprocess
import sys

from compare import read_pcapng, require, transactions


def values(root, name):
    return [int(value) for value in (root / name).read_text().strip().split(',')]


def validate(root):
    events = read_pcapng(root / 'edges.pcapng')
    channels = transactions(events, 'edge cases')
    pairs = [pair for channel in channels.values() for pair in channel]
    statuses = values(root, 'edge-status.txt')
    lengths = values(root, 'edge-lengths.txt')
    require(statuses == [-121, -32, -22, -2], 'fixture did not reach all expected error paths')
    require(lengths[:3] == [18, 0, 0], 'unexpected control/error lengths')

    for index, setup in enumerate([bytes.fromhex('8006000100004000'),
                                   bytes.fromhex('c0ff000000004000')]):
        selected = [p for p in pairs if p[0].setup == setup]
        require(len(selected) == 1, 'missing or duplicated error control request')
        submit, complete = selected[0]
        require(complete.fields['event'] == ord('C'), 'control request did not complete')
        require(complete.fields['status'] == statuses[index], 'control completion status mismatch')
        require(complete.fields['length'] == lengths[index], 'control completion length mismatch')
        expected = bytes(values(root, 'short-data.txt')) if index == 0 else b''
        require(complete.payload == expected, 'control completion payload mismatch')
        require(submit.fields['length'] == 64, 'lost requested control length')
        if index == 0:
            require(submit.fields['flags'] & 1, 'short transfer did not request SHORT_NOT_OK')

    rejected = [p for p in pairs if p[-1].fields['event'] == ord('E')]
    require(len(rejected) == 1, 'missing or duplicated submission error')
    submit, error = rejected[0]
    require(submit.fields['type'] == 1 and submit.fields['device'] == 1,
            'submission failure did not reach the root-hub interrupt endpoint')
    require(error.fields['status'] == statuses[2] and error.fields['length'] == 0,
            'submission error status/length mismatch')
    require(not submit.payload and not error.payload, 'unexpected enqueue-error payload')

    iso = [p for p in pairs if p[0].fields['type'] == 0]
    require(len(iso) == 2, 'missing overlapping or cancelled ISO URB')
    for name, pair in zip(['overlap', 'cancel'], iso):
        submit, complete = pair
        actual = values(root, name + '-lengths.txt')
        frame_status = values(root, name + '-status.txt')
        require(len(actual) == len(frame_status) == 137, 'missing independent ISO results')
        require(len(submit.iso) == len(complete.iso) == 137, 'lost ISO descriptors')
        require(complete.fields['event'] == ord('C'), 'ISO request did not complete')
        require(complete.fields['status'] == (0 if name == 'overlap' else statuses[3]),
                'ISO completion status mismatch')
        require(complete.fields['length'] == sum(actual), 'ISO completion actual length mismatch')
        if name == 'cancel':
            require(complete.fields['length'] == lengths[3], 'cancelled URB length mismatch')
        span = (68 if name == 'overlap' else 136) * 224 + 192
        expected = bytearray(span)
        for i in range(137):
            offset = (i // 2 if name == 'overlap' else i) * 224
            length = 192 if i % 3 else 188
            require(submit.iso[i][1:] == (offset, length), 'ISO submission offsets/lengths differ')
            require(complete.iso[i] == (frame_status[i], offset, actual[i]),
                    'ISO completion differs from the driver callback')
            expected[offset:offset + length] = bytes((i * 13 + j * 7) % 251 for j in range(length))
        require(submit.payload == expected, 'ISO shared/sparse buffer contents differ')
        require(not complete.payload, 'ISO OUT completion duplicated submission data')

    log = (root / 'edges.log').read_text()
    require('1 submit errors' in log, 'submission failure was not counted')
    require('0 ring losses, 0 read errors, 0 unsupported buffers, 0 state errors' in log,
            'USB protocol errors became capture loss')
    original = (root / 'edges.pcapng').read_bytes()
    for replay in ['edges-replay.pcapng', 'edges-roundtrip.pcapng']:
        require((root / replay).read_bytes() == original, 'replay changed edge-case events')
    decoded = subprocess.run(['tshark', '-r', str(root / 'edges.pcapng'), '-T', 'fields',
                              '-e', 'usb.urb_type'], capture_output=True, text=True, check=True)
    require(len(decoded.stdout.splitlines()) == len(events), 'TShark missed edge-case events')
    print('EDGE_E2E_PASS: shared ISO buffers, short-not-ok, STALL, HCD enqueue failure, '
          'cancellation, exact replay, and zero capture losses')


if __name__ == '__main__':
    validate(Path(sys.argv[1]))
