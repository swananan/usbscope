#!/usr/bin/env python3
"""Verify that the differential checker rejects damage to actual VM captures."""
import argparse
from copy import deepcopy
import json
from pathlib import Path

from compare import compare, read_pcap, read_pcapng


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('artifacts', type=Path)
    args = parser.parse_args()
    original = read_pcapng(args.artifacts / 'live.pcapng')
    baseline, snaplen = read_pcap(args.artifacts / 'tcpdump.pcap')
    compare(original, baseline, snaplen)
    rejected = []

    def reject(label, own, reference=baseline):
        try:
            compare(own, reference, snaplen)
        except AssertionError:
            rejected.append(label)
        else:
            raise AssertionError('checker accepted corrupted capture: ' + label)

    reject('missing completion', original[:-1])
    first_id = original[0].fields['id']
    pair = [event for event in original if event.fields['id'] == first_id]
    reject('missing whole URB', [event for event in original if event not in pair])
    reject('duplicated whole URB', original + pair)

    events = deepcopy(original)
    next(event for event in events if event.fields['event'] == ord('C')).fields['status'] ^= 1
    reject('wrong completion status', events)

    events = deepcopy(original)
    event = next(event for event in events if event.setup)
    event.setup = bytes([event.setup[0] ^ 1]) + event.setup[1:]
    reject('wrong control setup', events)

    events = deepcopy(original)
    event = next(event for event in events if len(event.payload) > 1_000_000)
    event.payload = bytes([event.payload[0] ^ 1]) + event.payload[1:]
    reject('corrupt payload byte', events)

    events = deepcopy(original)
    event = next(event for event in events if len(event.payload) > 1_000_000)
    event.payload = event.payload[:-1]
    reject('usbscope truncation beyond reference prefix', events)

    reference = deepcopy(baseline)
    event = next(event for event in reference if event.payload)
    event.payload = event.payload[:-1]
    reject('unexplained reference truncation', original, reference)

    if any(event.iso for event in original):
        events = deepcopy(original)
        event = next(event for event in events if event.iso)
        status, offset, length = event.iso[0]
        event.iso[0] = (status, offset + 1, length)
        reject('wrong ISO descriptor', events)

        reference = deepcopy(baseline)
        next(event for event in reference if event.iso).iso.pop()
        reject('unexplained reference descriptor loss', original, reference)

    (args.artifacts / 'comparison-negative.json').write_text(json.dumps(rejected, indent=2) + '\n')
    print(f'COMPARISON_GUARDS_PASS: {len(rejected)} corrupted captures rejected')


if __name__ == '__main__':
    main()
