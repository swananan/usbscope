#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{fentry, map},
    maps::RingBuf,
    programs::FEntryContext,
};
use usbscope_common::*;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024, 0);

unsafe extern "C" {
    fn core_read_urb(address: u64, meta: *mut EventMeta, buffer: *mut u64, sg: *mut u32) -> i64;
}

#[repr(C)]
struct Begin {
    header: RecordHeader,
    meta: EventMeta,
}

#[fentry]
pub fn observe_submit(ctx: FEntryContext) -> u32 {
    unsafe {
        emit(ctx.arg::<u64>(0));
    }
    0
}

unsafe fn emit(address: u64) {
    let Some(mut reservation) = EVENTS.reserve::<Begin>(0) else {
        return;
    };
    let item = reservation.as_mut_ptr();
    unsafe {
        (*item).header = RecordHeader {
            version: ABI_VERSION,
            kind: RECORD_BEGIN,
            size: 96,
            event_id: address,
            offset: 0,
        };
        (*item).meta = EventMeta {
            event_type: b'S',
            ..EventMeta::default()
        };
        let mut buffer = 0;
        let mut sg = 0;
        if core_read_urb(address, &mut (*item).meta, &mut buffer, &mut sg) < 0 {
            reservation.discard(0);
        } else {
            reservation.submit(0);
        }
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
