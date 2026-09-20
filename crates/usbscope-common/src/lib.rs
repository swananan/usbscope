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
    /// Addresses of x86_64 direct-map layout variables; zero disables SG.
    pub vmemmap_symbol: u64,
    pub page_offset_symbol: u64,
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

/// Ring transport ABI. Supported targets are little endian. `size` excludes
/// unused bytes in the reservation; consumers never persist those bytes.
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

const _: () = assert!(core::mem::size_of::<RecordHeader>() == 24);
const _: () = assert!(core::mem::size_of::<EventMeta>() == 72);
const _: () = assert!(core::mem::size_of::<IsoDescriptor>() == 16);
const _: () = assert!(core::mem::size_of::<EventEnd>() == 16);
