use std::collections::BTreeMap;
use usbscope_capture::Event;

#[derive(Default)]
struct Endpoint {
    urbs: u64,
    frames: u64,
    bytes: u64,
    frame_errors: u64,
    urb_errors: u64,
    empty_frames: u64,
    previous_ns: Option<u64>,
    max_gap_ns: u64,
}

/// URB completion timing is a software observation, not USB wire timing.
#[derive(Default)]
pub struct IsoStats(BTreeMap<(u64, u16, u8, u8), Endpoint>);

impl IsoStats {
    pub fn observe(&mut self, event: &Event) {
        let m = &event.meta;
        if m.transfer_type != 0 || m.event_type != b'C' {
            return;
        }
        let endpoint = self
            .0
            .entry((event.source_id, m.bus, m.device, m.endpoint))
            .or_default();
        endpoint.urbs += 1;
        endpoint.urb_errors += u64::from(m.status != 0);
        for descriptor in &event.iso {
            endpoint.frames += 1;
            endpoint.bytes += u64::from(descriptor.length);
            endpoint.frame_errors += u64::from(descriptor.status != 0);
            endpoint.empty_frames += u64::from(descriptor.length == 0);
        }
        if let Some(previous) = endpoint.previous_ns {
            endpoint.max_gap_ns = endpoint
                .max_gap_ns
                .max(m.timestamp_ns.saturating_sub(previous));
        }
        endpoint.previous_ns = Some(m.timestamp_ns);
    }

    pub fn report(&self) {
        for ((source, bus, device, address), ep) in &self.0 {
            eprintln!(
                "ISO usb{bus} {device:03} ep={address:02x} source={source}: {} completed URBs, {} frames, {} bytes, {} frame errors, {} URB errors, {} empty frames; max observed completion gap={} us",
                ep.urbs,
                ep.frames,
                ep.bytes,
                ep.frame_errors,
                ep.urb_errors,
                ep.empty_frames,
                ep.max_gap_ns / 1000
            );
        }
    }
}
