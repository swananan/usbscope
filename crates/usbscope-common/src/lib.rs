#![no_std]

pub const ABI_VERSION: u16 = 1;
pub const RAW_MAGIC: [u8; 8] = *b"USBSCP\0\x01";
pub const CHUNK_SIZE: usize = 16 * 1024;
pub const RECORD_BEGIN: u16 = 1;
pub const RECORD_DATA: u16 = 2;
pub const RECORD_ISO: u16 = 3;
pub const RECORD_END: u16 = 4;
/// Userspace appends final independent kernel counters to a raw archive.
pub const RECORD_STATS: u16 = 5;
pub const COMPLETE: u32 = 0;
pub const LOSS_RING: u32 = 1;
pub const LOSS_READ: u32 = 2;
pub const LOSS_UNSUPPORTED_BUFFER: u32 = 3;
pub const MAX_KERNEL_PREDICATES: u32 = 64;
pub const BPF_BUILD_MAGIC: [u8; 8] = *b"USBSBPF1";
pub const SG_ARM64_LEGACY: u32 = 1;
pub const SG_ARM64_COMPACT: u32 = 2;

#[repr(C)]
pub struct BpfBuildInfo {
    pub magic: [u8; 8],
    pub architecture: u32,
    pub config_size: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SgMemory {
    /// x86_64 kernel variables, read by BPF after relocation of struct page.
    pub vmemmap_symbol: u64,
    pub page_offset_symbol: u64,
    /// Zero disables SG. arm64 additionally needs CONFIG_ARM64_VA_BITS.
    pub page_shift: u32,
    pub va_bits: u32,
    /// arm64 vmemmap placement changed in upstream Linux 6.9.
    pub layout: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct KernelPredicate {
    pub value: u64,
    pub mask: u64,
    pub field: u32,
    pub comparison: u32,
}

impl KernelPredicate {
    #[inline(always)]
    pub fn matches(&self, meta: &EventMeta) -> bool {
        let value = match self.field {
            1 => u64::from(meta.bus),
            2 => u64::from(meta.device),
            3 => u64::from(meta.vid),
            4 => u64::from(meta.pid),
            5 => u64::from(meta.endpoint),
            6 => u64::from(meta.endpoint & 15),
            7 => u64::from(meta.endpoint >> 7),
            8 => u64::from(meta.transfer_type),
            9 => u64::from(meta.requested_len),
            10 => u64::from(meta.iso_count),
            _ => return true,
        } & self.mask;
        match self.comparison {
            0 => value == self.value,
            1 => value != self.value,
            2 => value < self.value,
            3 => value <= self.value,
            4 => value > self.value,
            5 => value >= self.value,
            _ => true,
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for KernelPredicate {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CaptureConfig {
    pub epoch_offset_ns: u64,
    pub giveback_start: u64,
    pub giveback_end: u64,
    pub memory: SgMemory,
    /// Zero selects all buses; u32::MAX selects all device addresses.
    pub bus: u32,
    pub device: u32,
    pub enabled: u32,
    pub filter_count: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CaptureStats {
    pub submitted: u64,
    pub completed: u64,
    pub submit_errors: u64,
    pub ring_losses: u64,
    pub read_errors: u64,
    pub unsupported_buffers: u64,
    pub state_errors: u64,
    pub sg_events: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for CaptureConfig {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for CaptureStats {}

/// Ring/archive transport ABI: all multibyte scalars are little endian,
/// independently of the host and BPF target. Maps and C accessor results use
/// native byte order; convert only when publishing a ring record. `size`
/// excludes unused reservation bytes, which consumers never persist.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct RecordHeader {
    pub version: u16,
    pub kind: u16,
    pub size: u32,
    pub event_id: u64,
    pub offset: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct EventMeta {
    pub urb_id: u64,
    pub timestamp_ns: u64,
    pub bus: u16,
    pub device: u8,
    pub endpoint: u8,
    /// usbmon encoding: ISO=0, interrupt=1, control=2, bulk=3.
    pub transfer_type: u8,
    pub event_type: u8,
    pub setup_present: u8,
    pub has_data: u8,
    pub status: i32,
    pub requested_len: u32,
    pub actual_len: u32,
    /// Address span including padding between ISO packets.
    pub payload_len: u32,
    pub interval: i32,
    pub start_frame: i32,
    pub transfer_flags: u32,
    pub iso_count: u32,
    pub error_count: i32,
    pub vid: u16,
    pub pid: u16,
    pub setup: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IsoDescriptor {
    pub status: i32,
    pub offset: u32,
    pub length: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct EventEnd {
    pub copied_bytes: u64,
    pub descriptors: u32,
    pub reason: u32,
}

impl RecordHeader {
    #[inline(always)]
    pub fn to_le(self) -> Self {
        Self {
            version: self.version.to_le(),
            kind: self.kind.to_le(),
            size: self.size.to_le(),
            event_id: self.event_id.to_le(),
            offset: self.offset.to_le(),
        }
    }
}

impl EventMeta {
    #[inline(always)]
    pub fn to_le(mut self) -> Self {
        self.encode_le();
        self
    }

    /// Convert an initialized record at its destination, avoiding a second
    /// metadata copy on the limited BPF stack. Call exactly once before publish.
    #[inline(always)]
    pub fn encode_le(&mut self) {
        self.urb_id = self.urb_id.to_le();
        self.timestamp_ns = self.timestamp_ns.to_le();
        self.bus = self.bus.to_le();
        self.status = self.status.to_le();
        self.requested_len = self.requested_len.to_le();
        self.actual_len = self.actual_len.to_le();
        self.payload_len = self.payload_len.to_le();
        self.interval = self.interval.to_le();
        self.start_frame = self.start_frame.to_le();
        self.transfer_flags = self.transfer_flags.to_le();
        self.iso_count = self.iso_count.to_le();
        self.error_count = self.error_count.to_le();
        self.vid = self.vid.to_le();
        self.pid = self.pid.to_le();
    }
}

impl IsoDescriptor {
    #[inline(always)]
    pub fn to_le(self) -> Self {
        Self {
            status: self.status.to_le(),
            offset: self.offset.to_le(),
            length: self.length.to_le(),
            padding: self.padding.to_le(),
        }
    }
}

impl EventEnd {
    #[inline(always)]
    pub fn to_le(self) -> Self {
        Self {
            copied_bytes: self.copied_bytes.to_le(),
            descriptors: self.descriptors.to_le(),
            reason: self.reason.to_le(),
        }
    }
}

const _: () = assert!(core::mem::size_of::<RecordHeader>() == 24);
const _: () = assert!(core::mem::size_of::<EventMeta>() == 72);
const _: () = assert!(core::mem::size_of::<IsoDescriptor>() == 16);
const _: () = assert!(core::mem::size_of::<EventEnd>() == 16);

#[cfg(test)]
mod tests {
    use super::*;

    // These four repr(C) records have no implicit padding. Test the actual
    // bytes published by BPF against fixed vectors, also on big-endian CPUs.
    fn bytes<T>(value: &T) -> &[u8] {
        unsafe { core::slice::from_raw_parts(core::ptr::from_ref(value).cast(), size_of::<T>()) }
    }

    #[test]
    fn wire_records_keep_the_v1_little_endian_format() {
        let header = RecordHeader {
            version: 1,
            kind: 3,
            size: 40,
            event_id: 0x0102_0304_0506_0708,
            offset: 0x1122_3344,
        }
        .to_le();
        assert_eq!(
            bytes(&header),
            [
                1, 0, 3, 0, 40, 0, 0, 0, 8, 7, 6, 5, 4, 3, 2, 1, 0x44, 0x33, 0x22, 0x11, 0, 0, 0,
                0,
            ]
        );
        let descriptor = IsoDescriptor {
            status: -121,
            offset: 0x1234_5678,
            length: 192,
            padding: 0,
        }
        .to_le();
        assert_eq!(
            bytes(&descriptor),
            [
                0x87, 0xff, 0xff, 0xff, 0x78, 0x56, 0x34, 0x12, 192, 0, 0, 0, 0, 0, 0, 0,
            ]
        );
        let end = EventEnd {
            copied_bytes: 0x0102_0304_0506_0708,
            descriptors: 137,
            reason: 3,
        }
        .to_le();
        assert_eq!(
            bytes(&end),
            [8, 7, 6, 5, 4, 3, 2, 1, 137, 0, 0, 0, 3, 0, 0, 0]
        );
    }

    #[test]
    fn metadata_encodes_scalars_and_preserves_usb_setup_bytes() {
        let meta = EventMeta {
            urb_id: 0x0102_0304_0506_0708,
            timestamp_ns: 0x1112_1314_1516_1718,
            bus: 0x1234,
            device: 7,
            endpoint: 0x81,
            transfer_type: 0,
            event_type: b'C',
            setup_present: 1,
            has_data: 1,
            status: -121,
            requested_len: 0x1122_3344,
            actual_len: 0x1234_5678,
            payload_len: 0x1122_0001,
            interval: -2,
            start_frame: 0x0102_0304,
            transfer_flags: 0xaabb_ccdd,
            iso_count: 137,
            error_count: -5,
            vid: 0x1234,
            pid: 0xabcd,
            setup: [0x80, 6, 0, 1, 0, 0, 18, 0],
        }
        .to_le();
        assert_eq!(
            bytes(&meta),
            [
                8, 7, 6, 5, 4, 3, 2, 1, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x34, 0x12,
                7, 0x81, 0, b'C', 1, 1, 0x87, 0xff, 0xff, 0xff, 0x44, 0x33, 0x22, 0x11, 0x78, 0x56,
                0x34, 0x12, 1, 0, 0x22, 0x11, 0xfe, 0xff, 0xff, 0xff, 4, 3, 2, 1, 0xdd, 0xcc, 0xbb,
                0xaa, 137, 0, 0, 0, 0xfb, 0xff, 0xff, 0xff, 0x34, 0x12, 0xcd, 0xab, 0x80, 6, 0, 1,
                0, 0, 18, 0,
            ]
        );
    }
}
