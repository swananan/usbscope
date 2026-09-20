#!/usr/bin/env python3
"""Compare independently captured tcpdump/usbmon and usbscope fixture traffic.

This intentionally does not use the product's readers or filter implementation.
Only the little-endian LINKTYPE 220 formats produced by this x86_64 VM are read.
"""
import argparse
from collections import defaultdict
from dataclasses import dataclass
import json
from pathlib import Path
import re
import struct
import subprocess


def require(condition, message):
    if not condition:
        raise AssertionError(message)


FIELDS = {
    'id': ('Q', 0), 'event': ('B', 8), 'type': ('B', 9),
    'endpoint': ('B', 10), 'device': ('B', 11), 'bus': ('H', 12),
    'status': ('i', 28), 'length': ('I', 32), 'data_length': ('I', 36),
    'errors': ('i', 40), 'frames': ('I', 44), 'interval': ('i', 48),
    'start_frame': ('i', 52), 'flags': ('I', 56), 'descriptors': ('I', 60),
}


@dataclass
class Event:
    fields: dict
    setup: bytes | None
    iso: list
    payload: bytes
    timestamp_us: int

    @property
    def channel(self):
        return tuple(self.fields[f] for f in ('bus', 'device', 'type', 'endpoint'))


def decode(data, timestamp_us):
    require(len(data) >= 64, 'short USB pseudoheader')
    fields = {name: struct.unpack_from('<' + fmt, data, offset)[0]
              for name, (fmt, offset) in FIELDS.items()}
    require(fields['event'] in b'SCE', 'unexpected USB event')
    require(fields['type'] <= 3, 'invalid transfer type')
    count = fields['descriptors']
    require(64 + count * 16 <= len(data), 'truncated descriptor list')
    require(fields['data_length'] >= len(data) - 64, 'invalid USB data length')
    require(fields['type'] == 0 or count == 0, 'ISO descriptors on a non-ISO event')
    require(len(data) == 64 + count * 16 or data[15] == 0, 'payload without data flag')
    iso = [struct.unpack_from('<iII', data, 64 + i * 16) for i in range(count)]
    return Event(fields, data[40:48] if data[14] == 0 else None,
                 iso, data[64 + count * 16:], timestamp_us)


def read_pcap(path):
    data = path.read_bytes()
    require(len(data) >= 24 and data[:4] == bytes.fromhex('d4c3b2a1'),
            'expected little-endian microsecond pcap from tcpdump')
    require(struct.unpack_from('<HH', data, 4) == (2, 4), 'unsupported pcap version')
    snaplen, linktype = struct.unpack_from('<II', data, 16)
    require(linktype == 220 and snaplen > 64, 'tcpdump must use USB_LINUX_MMAPPED')
    offset, events = 24, []
    while offset < len(data):
        require(offset + 16 <= len(data), 'truncated pcap record header')
        sec, usec, captured, original = struct.unpack_from('<IIII', data, offset)
        offset += 16
        require(captured <= original and captured <= snaplen, 'invalid pcap packet lengths')
        require(offset + captured <= len(data), 'truncated pcap packet')
        events.append(decode(data[offset:offset + captured], sec * 1_000_000 + usec))
        offset += captured
    return events, snaplen


def read_pcapng(path):
    data = path.read_bytes()
    require(data[:12] == struct.pack('<III', 0x0a0d0d0a, 28, 0x1a2b3c4d),
            'expected little-endian usbscope pcapng')
    offset, events, interfaces = 0, [], 0
    while offset < len(data):
        require(offset + 12 <= len(data), 'truncated pcapng block')
        kind, size = struct.unpack_from('<II', data, offset)
        require(size >= 12 and size % 4 == 0 and offset + size <= len(data),
                'invalid pcapng block size')
        require(struct.unpack_from('<I', data, offset + size - 4)[0] == size,
                'pcapng block lengths disagree')
        if kind == 1:
            require(size == 20 and struct.unpack_from('<H', data, offset + 8)[0] == 220,
                    'expected default microsecond LINKTYPE 220 interface')
            interfaces += 1
        elif kind == 6:
            require(size >= 32, 'short pcapng packet block')
            interface, hi, lo, captured, original = struct.unpack_from('<IIIII', data, offset + 8)
            require(interface < interfaces and captured == original, 'incomplete usbscope packet')
            require(size == 32 + ((captured + 3) & ~3), 'invalid usbscope packet span')
            event = decode(data[offset + 28:offset + 28 + captured], (hi << 32) | lo)
            require(event.fields['data_length'] == captured - 64, 'incorrect usbscope data length')
            events.append(event)
        else:
            require(kind == 0x0a0d0d0a, 'unexpected usbscope block')
        offset += size
    return events


def transactions(events, label):
    """Normalize IDs per submission, including usbmon's reuse of URB pointers."""
    channels, pending = defaultdict(list), {}
    for event in events:
        ident, phase = event.fields['id'], event.fields['event']
        if phase == ord('S'):
            require(ident not in pending, f'{label}: duplicate in-flight submission')
            pair = [event]
            pending[ident] = pair
            channels[event.channel].append(pair)
        else:
            require(ident in pending, f'{label}: completion/error without submission')
            pair = pending.pop(ident)
            require(pair[0].channel == event.channel, f'{label}: URB changed endpoint')
            require(pair[0].timestamp_us <= event.timestamp_us, f'{label}: completion precedes submission')
            pair.append(event)
    require(not pending, f'{label}: unfinished submissions')
    return channels


def compare(scope_events, reference_events, snaplen):
    require(scope_events and reference_events, 'both collectors must capture traffic')
    scope = transactions(scope_events, 'usbscope')
    reference = transactions(reference_events, 'tcpdump')
    require(scope.keys() == reference.keys(), 'collectors observed different USB endpoints')
    report = dict(events=len(scope_events), urbs=0, payload_bytes_compared=0,
                  iso_descriptors_compared=0, baseline_payload_truncations=0,
                  baseline_descriptor_truncations=0, max_timestamp_delta_us=0,
                  reference_snaplen=snaplen)
    for channel, pairs in scope.items():
        other = reference[channel]
        require(len(pairs) == len(other), f'{channel}: submission counts differ')
        for ordinal, (left, right) in enumerate(zip(pairs, other)):
            report['urbs'] += 1
            for own, ref in zip(left, right):
                a, b = own.fields, ref.fields
                context = f'{channel} URB {ordinal} {chr(a["event"])}'
                fields = ['event', 'status', 'length', 'flags']
                if a['type'] in (0, 1):
                    fields += ['interval']
                if a['type'] == 0:
                    fields += ['frames', 'errors', 'start_frame']
                for name in fields:
                    require(a[name] == b[name], f'{context}: {name}: {a[name]} != {b[name]}')
                require(own.setup == ref.setup, f'{context}: setup differs')
                delta = abs(own.timestamp_us - ref.timestamp_us)
                report['max_timestamp_delta_us'] = max(report['max_timestamp_delta_us'], delta)

                # These pinned kernels export at most 128 usbmon ISO descriptors.
                # An arbitrary smaller list is a failure, not an accepted mismatch.
                count = a['frames'] if a['type'] == 0 else 0
                require(len(own.iso) == count, f'{context}: usbscope lost descriptors')
                require(len(ref.iso) == min(count, 128), f'{context}: unexpected usbmon descriptor count')
                require(own.iso[:len(ref.iso)] == ref.iso, f'{context}: ISO descriptors differ')
                report['iso_descriptors_compared'] += len(ref.iso)
                report['baseline_descriptor_truncations'] += len(ref.iso) < count

                data_phase = (a['event'] == ord('S') and not a['endpoint'] & 0x80
                              or a['event'] == ord('C') and a['endpoint'] & 0x80)
                if not data_phase:
                    require(not own.payload and not ref.payload, f'{context}: payload on wrong phase')
                    continue
                if a['type'] == 0:
                    own_span = max((off + length for _, off, length in own.iso if length), default=0)
                    ref_span = (b['length'] if b['event'] == ord('S') else
                                max((off + length for _, off, length in ref.iso if length), default=0))
                else:
                    own_span, ref_span = a['length'], b['length']
                require(len(own.payload) == own_span, f'{context}: usbscope payload is incomplete')
                expected = min(ref_span, snaplen - 64 - len(ref.iso) * 16)
                require(len(ref.payload) == expected,
                        f'{context}: unexpected reference truncation: {len(ref.payload)} != {expected}')
                report['baseline_payload_truncations'] += expected < ref_span
                if a['type'] == 0:
                    # usbmon copies buffer gaps; usbscope zero-fills them. Compare
                    # valid regions described independently by usbmon, not gaps.
                    ranges = [(off, min(off + length, expected)) for _, off, length in ref.iso]
                else:
                    ranges = [(0, expected)]
                for start, end in ranges:
                    if end <= start:
                        continue
                    require(own.payload[start:end] == ref.payload[start:end],
                            f'{context}: payload differs in [{start}, {end})')
                    report['payload_bytes_compared'] += end - start
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('artifacts', type=Path)
    parser.add_argument('--audio', action='store_true')
    args = parser.parse_args()
    root = args.artifacts
    scope = read_pcapng(root / 'live.pcapng')
    reference, snaplen = read_pcap(root / 'tcpdump.pcap')
    require(snaplen >= 64 + 65536, 'reference must retain at least 64 KiB of each large payload')
    log = (root / 'tcpdump.log').read_text()
    for phrase, expected in [('packets captured', len(reference)),
                             ('packets received by filter', len(reference)),
                             ('packets dropped by kernel', 0)]:
        match = re.search(r'^(\d+) ' + phrase + '$', log, re.MULTILINE)
        require(match and int(match[1]) == expected, f'tcpdump statistics missing or incorrect: {phrase}')
    report = compare(scope, reference, snaplen)
    require(report['events'] >= 18, 'bulk/control fixture traffic is missing')
    require(report['payload_bytes_compared'] >= 2 * min(2_097_664, snaplen - 64),
            'large transfers were not compared in both directions')
    if args.audio:
        require(report['iso_descriptors_compared'] == 256, 'both 137-frame ISO events must be compared')
        require(report['baseline_descriptor_truncations'] == 2, 'expected 128/137 usbmon boundary')
    # Decode both independent captures with the same external decoder as well.
    for name, events in [('live.pcapng', scope), ('tcpdump.pcap', reference)]:
        decoded = subprocess.run(['tshark', '-r', str(root / name), '-T', 'fields',
                                  '-e', 'usb.urb_type'], capture_output=True, text=True, check=True)
        require(len(decoded.stdout.splitlines()) == len(events), f'TShark did not decode every event in {name}')
    report['tcpdump_version'] = (root / 'tcpdump-version.txt').read_text().strip()
    (root / 'comparison.json').write_text(json.dumps(report, indent=2) + '\n')
    print('TCPDUMP_E2E_PASS: ' + json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
