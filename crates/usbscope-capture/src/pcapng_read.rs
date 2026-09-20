//! Streaming pcapng reader for complete LINKTYPE_USB_LINUX_MMAPPED records.
//! Packet lengths are validated against their enclosing block before allocation.
use crate::{Event, SPOOL_MEMORY};
use anyhow::{Context, Result, bail, ensure};
use std::{
    collections::HashMap,
    io::{Read, Write},
};
use tempfile::SpooledTempFile;
use usbscope_common::{EventMeta, IsoDescriptor};

#[derive(Clone, Copy, Default)]
enum Endian {
    #[default]
    Little,
    Big,
}
impl Endian {
    fn u16(self, b: &[u8]) -> u16 {
        match self {
            Self::Little => u16::from_le_bytes(b[..2].try_into().unwrap()),
            Self::Big => u16::from_be_bytes(b[..2].try_into().unwrap()),
        }
    }
    fn u32(self, b: &[u8]) -> u32 {
        match self {
            Self::Little => u32::from_le_bytes(b[..4].try_into().unwrap()),
            Self::Big => u32::from_be_bytes(b[..4].try_into().unwrap()),
        }
    }
    fn u64(self, b: &[u8]) -> u64 {
        match self {
            Self::Little => u64::from_le_bytes(b[..8].try_into().unwrap()),
            Self::Big => u64::from_be_bytes(b[..8].try_into().unwrap()),
        }
    }
}
struct Interface {
    linktype: u16,
    units: u64,
    offset: i64,
}
pub struct Reader<R> {
    input: R,
    endian: Endian,
    section: bool,
    interfaces: Vec<Interface>,
    requested: HashMap<u64, u32>,
    pub incomplete: u64,
}
impl<R: Read> Reader<R> {
    pub fn new(input: R) -> Self {
        Self {
            input,
            endian: Endian::Little,
            section: false,
            interfaces: vec![],
            requested: HashMap::new(),
            incomplete: 0,
        }
    }
    pub fn next_event(&mut self) -> Result<Option<Event>> {
        loop {
            let mut header = [0u8; 8];
            if self.input.read(&mut header[..1])? == 0 {
                return Ok(None);
            }
            self.input
                .read_exact(&mut header[1..])
                .context("truncated pcapng block header")?;
            if header[..4] == [10, 13, 13, 10] {
                let mut magic = [0u8; 4];
                self.input.read_exact(&mut magic)?;
                self.endian = match magic {
                    [77, 60, 43, 26] => Endian::Little,
                    [26, 43, 60, 77] => Endian::Big,
                    _ => bail!("invalid pcapng byte order magic"),
                };
                let size = self.endian.u32(&header[4..]);
                ensure!(
                    size >= 28 && size.is_multiple_of(4),
                    "invalid pcapng section length"
                );
                let mut version = [0u8; 4];
                self.input.read_exact(&mut version)?;
                ensure!(self.endian.u16(&version) == 1, "unsupported pcapng version");
                skip(&mut self.input, u64::from(size - 20))?;
                self.footer(size)?;
                self.section = true;
                self.interfaces.clear();
                self.requested.clear();
                continue;
            }
            ensure!(self.section, "pcapng must start with a section header");
            let kind = self.endian.u32(&header);
            let size = self.endian.u32(&header[4..]);
            ensure!(
                size >= 12 && size.is_multiple_of(4),
                "invalid pcapng block length"
            );
            match kind {
                1 => {
                    ensure!(size >= 20, "short pcapng interface block");
                    let mut body = [0u8; 8];
                    self.input.read_exact(&mut body)?;
                    let mut interface = Interface {
                        linktype: self.endian.u16(&body),
                        units: 1_000_000,
                        offset: 0,
                    };
                    let mut remaining = size - 20;
                    while remaining >= 4 {
                        let mut option = [0u8; 4];
                        self.input.read_exact(&mut option)?;
                        let code = self.endian.u16(&option);
                        let length = u32::from(self.endian.u16(&option[2..]));
                        let padded = (length + 3) & !3;
                        remaining -= 4;
                        ensure!(padded <= remaining, "pcapng option outside block");
                        let mut value = vec![0u8; length as usize];
                        self.input.read_exact(&mut value)?;
                        skip(&mut self.input, u64::from(padded - length))?;
                        remaining -= padded;
                        if code == 9 {
                            ensure!(length == 1, "invalid timestamp resolution option");
                            interface.units = if value[0] & 128 != 0 {
                                2u64.checked_pow(u32::from(value[0] & 127))
                            } else {
                                10u64.checked_pow(u32::from(value[0]))
                            }
                            .context("timestamp resolution not representable")?;
                        } else if code == 14 {
                            ensure!(length == 8, "invalid timestamp offset option");
                            interface.offset = self.endian.u64(&value) as i64;
                        } else if code == 0 {
                            ensure!(length == 0, "invalid end-of-options");
                            break;
                        }
                    }
                    skip(&mut self.input, u64::from(remaining))?;
                    self.interfaces.push(interface);
                    self.footer(size)?;
                }
                6 => {
                    ensure!(size >= 32, "short pcapng packet block");
                    let mut packet = [0u8; 20];
                    self.input.read_exact(&mut packet)?;
                    let index = self.endian.u32(&packet) as usize;
                    let interface = self
                        .interfaces
                        .get(index)
                        .context("unknown pcapng interface")?;
                    ensure!(
                        interface.linktype == 220,
                        "only LINKTYPE_USB_LINUX_MMAPPED (220) is supported"
                    );
                    let ticks = (u64::from(self.endian.u32(&packet[4..])) << 32)
                        | u64::from(self.endian.u32(&packet[8..]));
                    let timestamp = i128::from(ticks) * 1_000_000_000 / i128::from(interface.units)
                        + i128::from(interface.offset) * 1_000_000_000;
                    let timestamp: u64 = timestamp
                        .try_into()
                        .context("packet timestamp out of range")?;
                    let caplen = self.endian.u32(&packet[12..]);
                    let original = self.endian.u32(&packet[16..]);
                    let padded = (u64::from(caplen) + 3) & !3;
                    ensure!(
                        padded <= u64::from(size - 32),
                        "packet length exceeds pcapng block"
                    );
                    if caplen < 64 || caplen < original {
                        skip(&mut self.input, u64::from(size - 32))?;
                        self.footer(size)?;
                        self.incomplete += 1;
                        continue;
                    }
                    ensure!(
                        caplen == original,
                        "captured length exceeds original length"
                    );
                    let mut usb = [0u8; 64];
                    self.input.read_exact(&mut usb)?;
                    // LINKTYPE 220 is a native-endian pseudoheader; pcapng's
                    // section byte order describes captures written by that host.
                    let mut meta = EventMeta {
                        urb_id: self.endian.u64(&usb),
                        timestamp_ns: timestamp,
                        bus: self.endian.u16(&usb[12..]),
                        device: usb[11],
                        endpoint: usb[10],
                        transfer_type: usb[9],
                        event_type: usb[8],
                        setup_present: u8::from(usb[14] == 0),
                        has_data: u8::from(usb[15] == 0),
                        status: self.endian.u32(&usb[28..]) as i32,
                        interval: self.endian.u32(&usb[48..]) as i32,
                        start_frame: self.endian.u32(&usb[52..]) as i32,
                        transfer_flags: self.endian.u32(&usb[56..]),
                        iso_count: self.endian.u32(&usb[60..]),
                        ..EventMeta::default()
                    };
                    ensure!(
                        matches!(meta.event_type, b'S' | b'C' | b'E')
                            && meta.transfer_type <= 3
                            && meta.device <= 127,
                        "invalid USB pseudoheader"
                    );
                    let wire_len = self.endian.u32(&usb[32..]);
                    let data_len = self.endian.u32(&usb[36..]);
                    ensure!(
                        data_len == caplen - 64,
                        "USB data length disagrees with packet length"
                    );
                    let desc_bytes = meta
                        .iso_count
                        .checked_mul(16)
                        .context("ISO descriptor size overflow")?;
                    ensure!(
                        desc_bytes <= data_len && (meta.transfer_type == 0 || meta.iso_count == 0),
                        "invalid ISO descriptor span"
                    );
                    meta.payload_len = data_len - desc_bytes;
                    ensure!(
                        meta.has_data != 0 || meta.payload_len == 0,
                        "USB payload without presence flag"
                    );
                    let requested_known = if meta.event_type == b'S' {
                        ensure!(
                            self.requested.len() < 65536,
                            "too many unmatched pcapng submissions"
                        );
                        self.requested.insert(meta.urb_id, wire_len);
                        meta.requested_len = wire_len;
                        true
                    } else {
                        meta.actual_len = wire_len;
                        let request = self.requested.remove(&meta.urb_id);
                        meta.requested_len = request.unwrap_or(0);
                        request.is_some()
                    };
                    let mut iso = Vec::new();
                    if meta.transfer_type == 0 {
                        meta.error_count = self.endian.u32(&usb[40..]) as i32;
                        ensure!(
                            self.endian.u32(&usb[44..]) == meta.iso_count,
                            "truncated ISO descriptor list"
                        );
                        for _ in 0..meta.iso_count {
                            let mut descriptor = [0u8; 16];
                            self.input.read_exact(&mut descriptor)?;
                            let d = IsoDescriptor {
                                status: self.endian.u32(&descriptor) as i32,
                                offset: self.endian.u32(&descriptor[4..]),
                                length: self.endian.u32(&descriptor[8..]),
                                padding: 0,
                            };
                            let end = u64::from(d.offset) + u64::from(d.length);
                            // A capture can start at completion, or filtering/
                            // rotation can remove its submission. ISO actual
                            // length excludes gaps and says nothing about the
                            // buffer extent, especially for empty tail frames.
                            ensure!(
                                end <= u64::from(u32::MAX)
                                    && (!requested_known || end <= u64::from(meta.requested_len)),
                                "ISO descriptor outside URB buffer"
                            );
                            if meta.has_data != 0 && d.length != 0 {
                                ensure!(
                                    end <= u64::from(meta.payload_len),
                                    "truncated ISO payload"
                                );
                            }
                            iso.push(d);
                        }
                    } else if meta.setup_present != 0 {
                        meta.setup.copy_from_slice(&usb[40..48]);
                    }
                    let mut payload = SpooledTempFile::new(SPOOL_MEMORY);
                    let copied = std::io::copy(
                        &mut (&mut self.input).take(u64::from(meta.payload_len)),
                        &mut payload,
                    )?;
                    ensure!(
                        copied == u64::from(meta.payload_len),
                        "truncated pcapng payload"
                    );
                    payload.flush()?;
                    skip(&mut self.input, u64::from(size - 32 - caplen))?;
                    self.footer(size)?;
                    if meta.transfer_type != 0 && meta.has_data != 0 && meta.payload_len != wire_len
                    {
                        self.incomplete += 1;
                        continue;
                    }
                    return Ok(Some(Event {
                        meta,
                        iso,
                        payload,
                        identity_known: false,
                        requested_known,
                    }));
                }
                2 | 3 => bail!(
                    "legacy/simple pcapng packet blocks are not supported; Enhanced Packet Blocks are required"
                ),
                _ => {
                    skip(&mut self.input, u64::from(size - 12))?;
                    self.footer(size)?;
                }
            }
        }
    }
    fn footer(&mut self, size: u32) -> Result<()> {
        let mut footer = [0u8; 4];
        self.input
            .read_exact(&mut footer)
            .context("truncated pcapng block")?;
        ensure!(
            self.endian.u32(&footer) == size,
            "pcapng block lengths disagree"
        );
        Ok(())
    }
}
fn skip(input: &mut impl Read, count: u64) -> Result<()> {
    let copied = std::io::copy(&mut input.take(count), &mut std::io::sink())?;
    ensure!(copied == count, "truncated pcapng block");
    Ok(())
}
