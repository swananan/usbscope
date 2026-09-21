use anyhow::{Context, Result, ensure};
use std::{
    collections::{BTreeMap, HashMap},
    io::{Read, Seek, SeekFrom, Write},
};
use tempfile::SpooledTempFile;
use usbscope_common::*;

pub mod filter;
pub mod pcapng;
pub mod pcapng_read;

pub struct Event {
    /// Distinguishes pcapng interfaces across sections; live/raw use source 0.
    /// URB IDs are only unique within one capture source.
    pub source_id: u64,
    pub meta: EventMeta,
    pub iso: Vec<IsoDescriptor>,
    pub payload: SpooledTempFile,
    /// Native Linux USB pcapng omits these fields; do not invent filter values.
    pub identity_known: bool,
    pub requested_known: bool,
}

struct Pending {
    event: Event,
    ranges: BTreeMap<u64, u64>,
    copied: u64,
}

#[derive(Default, Debug)]
pub struct ReassemblyStats {
    pub complete: u64,
    pub incomplete: u64,
    pub orphan_records: u64,
    pub kernel_losses: u64,
}

#[derive(Default)]
pub struct Reassembler {
    pending: HashMap<u64, Pending>,
    pub stats: ReassemblyStats,
}

// Per-record and memory bounds, never payload snap lengths.
pub const MAX_RECORD_SIZE: usize = CHUNK_SIZE + 24;
const SPOOL_MEMORY: usize = 1024 * 1024;
const MAX_PENDING_EVENTS: usize = 4096;

pub fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().unwrap())
}
pub fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
pub fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

pub fn decode_meta(b: &[u8]) -> Result<EventMeta> {
    ensure!(b.len() == 72, "invalid metadata length");
    let m = EventMeta {
        urb_id: u64_at(b, 0),
        timestamp_ns: u64_at(b, 8),
        bus: u16_at(b, 16),
        device: b[18],
        endpoint: b[19],
        transfer_type: b[20],
        event_type: b[21],
        setup_present: b[22],
        has_data: b[23],
        status: u32_at(b, 24) as i32,
        requested_len: u32_at(b, 28),
        actual_len: u32_at(b, 32),
        payload_len: u32_at(b, 36),
        interval: u32_at(b, 40) as i32,
        start_frame: u32_at(b, 44) as i32,
        transfer_flags: u32_at(b, 48),
        iso_count: u32_at(b, 52),
        error_count: u32_at(b, 56) as i32,
        vid: u16_at(b, 60),
        pid: u16_at(b, 62),
        setup: b[64..72].try_into().unwrap(),
    };
    ensure!(
        matches!(m.event_type, b'S' | b'C' | b'E'),
        "invalid URB event type"
    );
    ensure!(
        m.transfer_type <= 3 && m.device <= 127,
        "invalid USB metadata"
    );
    ensure!(
        m.has_data <= 1 && m.setup_present <= 1,
        "invalid presence flag"
    );
    ensure!(
        m.has_data != 0 || m.payload_len == 0,
        "payload without data flag"
    );
    ensure!(
        m.transfer_type == 0 || m.iso_count == 0,
        "ISO descriptors on non-ISO event"
    );
    ensure!(
        m.payload_len <= m.requested_len,
        "payload span exceeds URB buffer"
    );
    Ok(m)
}

impl Reassembler {
    pub fn push(&mut self, bytes: &[u8]) -> Result<Option<Event>> {
        ensure!(bytes.len() >= 24, "short record header");
        ensure!(u16_at(bytes, 0) == ABI_VERSION, "unsupported event ABI");
        let size = u32_at(bytes, 4) as usize;
        ensure!(
            (24..=MAX_RECORD_SIZE).contains(&size) && size <= bytes.len(),
            "invalid record size"
        );
        let kind = u16_at(bytes, 2);
        let id = u64_at(bytes, 8);
        let offset = u64_at(bytes, 16);
        let body = &bytes[24..size];
        if kind == RECORD_STATS {
            ensure!(
                id == 0 && offset == 0 && body.len() == 64,
                "invalid kernel counter summary"
            );
            for at in [24, 32, 40, 48] {
                self.stats.kernel_losses =
                    self.stats.kernel_losses.saturating_add(u64_at(body, at));
            }
            return Ok(None);
        }
        if kind == RECORD_BEGIN {
            ensure!(offset == 0, "metadata offset must be zero");
            ensure!(!self.pending.contains_key(&id), "duplicate event begin");
            ensure!(
                self.pending.len() < MAX_PENDING_EVENTS,
                "too many unfinished events; capture cannot keep up"
            );
            let meta = decode_meta(body)?;
            self.pending.insert(
                id,
                Pending {
                    event: Event {
                        source_id: 0,
                        meta,
                        iso: Vec::new(),
                        payload: SpooledTempFile::new(SPOOL_MEMORY),
                        identity_known: true,
                        requested_known: true,
                    },
                    ranges: BTreeMap::new(),
                    copied: 0,
                },
            );
            return Ok(None);
        }
        ensure!(
            matches!(kind, RECORD_DATA | RECORD_ISO | RECORD_END),
            "unknown record kind {kind}"
        );
        let Some(pending) = self.pending.get_mut(&id) else {
            self.stats.orphan_records += 1;
            return Ok(None);
        };
        match kind {
            RECORD_DATA => {
                ensure!(!body.is_empty(), "empty payload record");
                let end = offset
                    .checked_add(body.len() as u64)
                    .context("payload offset overflow")?;
                ensure!(
                    end <= u64::from(pending.event.meta.payload_len),
                    "payload outside declared span"
                );
                let previous = pending
                    .ranges
                    .range(..=offset)
                    .next_back()
                    .map(|(&a, &b)| (a, b));
                let next = pending.ranges.range(offset..).next().map(|(&a, &b)| (a, b));
                ensure!(
                    previous.is_none_or(|(_, b)| b <= offset),
                    "overlapping payload fragment"
                );
                ensure!(
                    next.is_none_or(|(a, _)| a >= end),
                    "overlapping payload fragment"
                );
                let mut start = offset;
                let mut merged_end = end;
                if let Some((a, _)) = previous.filter(|(_, b)| *b == offset) {
                    pending.ranges.remove(&a);
                    start = a;
                }
                if let Some((a, b)) = next.filter(|(a, _)| *a == end) {
                    pending.ranges.remove(&a);
                    merged_end = b;
                }
                pending.ranges.insert(start, merged_end);
                pending.event.payload.seek(SeekFrom::Start(offset))?;
                pending.event.payload.write_all(body)?;
                pending.copied += body.len() as u64;
            }
            RECORD_ISO => {
                ensure!(body.len() == 16, "invalid ISO descriptor length");
                ensure!(
                    offset == pending.event.iso.len() as u64
                        && offset < u64::from(pending.event.meta.iso_count),
                    "invalid ISO descriptor index"
                );
                pending.event.iso.push(IsoDescriptor {
                    status: u32_at(body, 0) as i32,
                    offset: u32_at(body, 4),
                    length: u32_at(body, 8),
                    padding: 0,
                });
            }
            RECORD_END => {
                ensure!(body.len() == 16 && offset == 0, "invalid event end");
                let pending = self.pending.remove(&id).unwrap();
                let m = &pending.event.meta;
                if m.transfer_type == 0 {
                    let mut span = 0u64;
                    for descriptor in &pending.event.iso {
                        let end = u64::from(descriptor.offset) + u64::from(descriptor.length);
                        ensure!(
                            end <= u64::from(m.requested_len),
                            "ISO descriptor outside URB buffer"
                        );
                        if descriptor.length != 0 {
                            span = span.max(end);
                        }
                    }
                    if m.has_data != 0 && pending.event.iso.len() as u64 == u64::from(m.iso_count) {
                        ensure!(
                            span == u64::from(m.payload_len),
                            "ISO descriptors disagree with payload span"
                        );
                    }
                }
                let covers =
                    |start: u64, len: u64| {
                        len == 0
                            || pending.ranges.range(..=start).next_back().is_some_and(
                                |(_, &end)| {
                                    start.checked_add(len).is_some_and(|limit| limit <= end)
                                },
                            )
                    };
                let data_complete = if m.has_data == 0 {
                    pending.copied == 0
                } else if m.transfer_type == 0 {
                    pending
                        .event
                        .iso
                        .iter()
                        .all(|d| covers(u64::from(d.offset), u64::from(d.length)))
                } else {
                    covers(0, u64::from(m.payload_len))
                };
                if u32_at(body, 12) != COMPLETE
                    || u64_at(body, 0) != pending.copied
                    || u32_at(body, 8) != m.iso_count
                    || pending.event.iso.len() as u64 != u64::from(m.iso_count)
                    || !data_complete
                {
                    self.stats.incomplete += 1;
                    return Ok(None);
                }
                self.stats.complete += 1;
                return Ok(Some(pending.event));
            }
            _ => unreachable!(),
        }
        Ok(None)
    }

    pub fn finish(&mut self) {
        self.stats.incomplete += self.pending.len() as u64;
        self.pending.clear();
    }
    /// A requested offline event/file limit is not evidence of transport loss.
    pub fn stop_at_limit(&mut self) {
        self.pending.clear();
    }
}

pub fn write_kernel_summary(writer: &mut impl Write, stats: &CaptureStats) -> Result<()> {
    writer.write_all(&88u32.to_le_bytes())?;
    writer.write_all(&ABI_VERSION.to_le_bytes())?;
    writer.write_all(&RECORD_STATS.to_le_bytes())?;
    writer.write_all(&88u32.to_le_bytes())?;
    writer.write_all(&[0u8; 16])?;
    for value in [
        stats.submitted,
        stats.completed,
        stats.submit_errors,
        stats.ring_losses,
        stats.read_errors,
        stats.unsupported_buffers,
        stats.state_errors,
        stats.sg_events,
    ] {
        writer.write_all(&value.to_le_bytes())?;
    }
    Ok(())
}

pub fn read_raw_header(reader: &mut impl Read) -> Result<()> {
    let mut magic = [0; 8];
    reader
        .read_exact(&mut magic)
        .context("reading capture header")?;
    ensure!(magic == RAW_MAGIC, "not a usbscope event archive");
    Ok(())
}

pub fn read_record(reader: &mut impl Read) -> Result<Option<Vec<u8>>> {
    let mut prefix = [0; 4];
    if reader.read(&mut prefix[..1])? == 0 {
        return Ok(None);
    }
    reader
        .read_exact(&mut prefix[1..])
        .context("truncated archive record length")?;
    let len = u32::from_le_bytes(prefix) as usize;
    ensure!(
        (24..=MAX_RECORD_SIZE).contains(&len),
        "invalid archive record length {len}"
    );
    let mut bytes = vec![0; len];
    reader
        .read_exact(&mut bytes)
        .context("truncated archive record")?;
    ensure!(
        u32_at(&bytes, 4) as usize == len,
        "archive and event lengths disagree"
    );
    Ok(Some(bytes))
}
