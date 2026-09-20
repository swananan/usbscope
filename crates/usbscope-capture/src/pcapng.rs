use crate::Event;
use anyhow::{Context, Result, ensure};
use std::io::{Read, Seek, SeekFrom, Write};

pub struct Writer<W> {
    output: W,
    bytes: u64,
}

impl<W: Write> Writer<W> {
    pub fn new(mut output: W) -> Result<Self> {
        block(
            &mut output,
            0x0a0d0d0a,
            &[
                0x4d, 0x3c, 0x2b, 0x1a, 1, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255,
            ],
        )?;
        // LINKTYPE_USB_LINUX_MMAPPED, no snap limit, microsecond timestamps.
        block(&mut output, 1, &[220, 0, 0, 0, 0, 0, 0, 0])?;
        Ok(Self { output, bytes: 48 })
    }

    pub fn write_event(&mut self, event: &mut Event) -> Result<()> {
        let m = &event.meta;
        let desc_len = u32::try_from(event.iso.len())
            .context("too many ISO descriptors")?
            .checked_mul(16)
            .context("ISO descriptor length overflow")?;
        let data_len = desc_len
            .checked_add(m.payload_len)
            .context("USB record exceeds format length")?;
        let caplen = 64u32
            .checked_add(data_len)
            .context("USB record exceeds format length")?;
        let padding = (4 - caplen % 4) % 4;
        let total = caplen
            .checked_add(padding + 32)
            .context("pcapng block exceeds format length")?;
        let ts = m.timestamp_ns / 1000;
        write_u32(&mut self.output, 6)?;
        write_u32(&mut self.output, total)?;
        for value in [0, (ts >> 32) as u32, ts as u32, caplen, caplen] {
            write_u32(&mut self.output, value)?;
        }
        let mut header = [0u8; 64];
        header[0..8].copy_from_slice(&m.urb_id.to_le_bytes());
        header[8] = m.event_type;
        header[9] = m.transfer_type;
        header[10] = m.endpoint;
        header[11] = m.device;
        header[12..14].copy_from_slice(&m.bus.to_le_bytes());
        header[14] = if m.setup_present != 0 { 0 } else { b'-' };
        header[15] = if m.has_data != 0 {
            0
        } else if m.endpoint & 0x80 != 0 {
            b'<'
        } else {
            b'>'
        };
        header[16..24].copy_from_slice(&((ts / 1_000_000) as i64).to_le_bytes());
        header[24..28].copy_from_slice(&((ts % 1_000_000) as u32).to_le_bytes());
        header[28..32].copy_from_slice(&m.status.to_le_bytes());
        let urb_len = if m.event_type == b'S' {
            m.requested_len
        } else {
            m.actual_len
        };
        header[32..36].copy_from_slice(&urb_len.to_le_bytes());
        header[36..40].copy_from_slice(&data_len.to_le_bytes());
        if m.transfer_type == 0 {
            header[40..44].copy_from_slice(&m.error_count.to_le_bytes());
            header[44..48].copy_from_slice(&m.iso_count.to_le_bytes());
        } else if m.setup_present != 0 {
            header[40..48].copy_from_slice(&m.setup);
        }
        header[48..52].copy_from_slice(&m.interval.to_le_bytes());
        header[52..56].copy_from_slice(&m.start_frame.to_le_bytes());
        header[56..60].copy_from_slice(&m.transfer_flags.to_le_bytes());
        header[60..64].copy_from_slice(&m.iso_count.to_le_bytes());
        self.output.write_all(&header)?;
        for d in &event.iso {
            for value in [d.status as u32, d.offset, d.length, 0] {
                write_u32(&mut self.output, value)?;
            }
        }
        event.payload.seek(SeekFrom::Start(0))?;
        let copied = std::io::copy(
            &mut (&mut event.payload).take(u64::from(m.payload_len)),
            &mut self.output,
        )?;
        ensure!(
            copied == u64::from(m.payload_len),
            "payload shorter than declared span"
        );
        self.output.write_all(&[0; 3][..padding as usize])?;
        write_u32(&mut self.output, total)?;
        self.bytes += u64::from(total);
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        self.output.flush()?;
        Ok(())
    }
    pub fn bytes_written(&self) -> u64 {
        self.bytes
    }
}

fn write_u32(w: &mut impl Write, value: u32) -> std::io::Result<()> {
    w.write_all(&value.to_le_bytes())
}
fn block(w: &mut impl Write, kind: u32, data: &[u8]) -> Result<()> {
    let len = u32::try_from(data.len())? + 12;
    write_u32(w, kind)?;
    write_u32(w, len)?;
    w.write_all(data)?;
    write_u32(w, len)?;
    Ok(())
}
