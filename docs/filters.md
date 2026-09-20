# USB capture filters

Expressions work with live capture and `-r` raw archives or USB pcapng files.
Quote shell operators:

```sh
usbscope -i usb2 -w disk.pcapng 'vid 0x1234 and pid 0x5678 and bulk'
usbscope -w failures.pcapng 'event complete and status != 0'
usbscope -r capture.usbraw -w slow.pcapng 'latency >= 2ms'
usbscope -r capture.usbraw 'control and setup.request 6 and setup.value & 0xff00 = 0x0100'
usbscope -w selected.pcapng 'bulk and out and payload[0:4] == 0x55534243'
usbscope -d 'bus 1 or payload contains "hello"'
usbscope -F filter.txt -w selected.pcapng
```

Precedence is `not`/`!`, then `and`/`&&`, then `or`/`||`. Parentheses override it.
Adjacent predicates imply `and`. Comparisons are `=`, `==`, `!=`, `<`, `<=`, `>`,
`>=`; omitted comparison means equality. Integers are decimal or `0x` hexadecimal.
Negative status values and an optional bit mask (`FIELD & MASK`) are supported.

| Field | Meaning |
| --- | --- |
| `bus`, `dev` / `device` | Bus number, device address |
| `vid`, `pid` | USB vendor/product ID from live metadata or raw archive |
| `ep` / `endpoint`, `epnum` | Full endpoint address including direction, or low four bits |
| `in`, `out`, `dir in/out` | Transfer direction |
| `control`, `bulk`, `interrupt`, `iso`, `type TYPE` | Transfer type |
| `event submit/complete/error` (or `S/C/E`) | Observation phase |
| `status` | Signed URB status; submission normally has `-115` |
| `requested`, `actual`, `len`, `captured` | Buffer length, actual completion length, phase-specific length, captured address span |
| `frames`, `errors`, `interval`, `start_frame` | ISO count, URB error count, kernel interval and start frame |
| `urb` | Session URB identifier |
| `setup.type/request/value/index/length` | Control setup fields, decoded as USB little endian values |
| `latency` | Completion/error timestamp minus the observed submission timestamp |
| `payload[OFFSET:WIDTH]` | Unsigned big endian byte extraction; widths 1 (default), 2, 4, 8 |
| `payload contains 0xHEX` or `payload contains "TEXT"` | Streaming byte search |

Latency values accept `ns` (default), `us`, `ms`, or `s`, with integer quantities.
It is software-observed URB latency, not transaction timing on the wire. Setup
fields are present on control submissions. Actual length and latency are absent
on submissions. No data, an out-of-range byte extraction, or a missing submission
makes the corresponding predicate unknown. Unknown does not match, even under
`not`. For ISO, byte filters exclude padding; `contains` searches within each
frame and does not stitch separate frames together.

Native USB pcapng does not carry VID/PID, so those fields are unknown when reading
pcapng. A completion's `requested` length is known only if its submission was
read earlier. Unknown fields do not become zero, and `not vid 0x1234` does not
select a packet whose VID was never recorded. Raw archives retain live metadata.

Filters select individual events. A setup or payload predicate can therefore
select one side of an S/C pair. Use stable device/endpoint/type predicates when
both sides are needed. Latency filtering retains submission timestamps before
applying the expression, so `event complete and latency > 1ms` works correctly.

Only necessary predicates over fields that remain unchanged between submission
and completion are pushed into BPF. Other conditions run after complete event
reassembly. `bus 1 or payload contains ...` must capture both branches, so it
cannot reject other buses in the kernel. `-d` displays the plan without loading
BPF. At most 64 necessary predicates are pushed; the complete expression is
always evaluated in userspace. The parser bounds nesting for stack safety;
flat expressions are balanced rather than recursively chained.

These are USB capture filters, not libpcap's Ethernet grammar or Wireshark display
filters. Interface class, device-path generations, UAC field decoding, and
pair-preserving selection are not part of this grammar yet.
