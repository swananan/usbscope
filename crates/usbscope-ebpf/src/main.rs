#![no_std]
#![no_main]
#![feature(core_intrinsics)]
#![allow(internal_features)]

use aya_ebpf::{
    helpers::{bpf_ktime_get_ns, bpf_probe_read_kernel, generated},
    macros::{fentry, fexit, kprobe, map},
    maps::{Array, HashMap, PerCpuArray, RingBuf},
    programs::{FEntryContext, FExitContext, ProbeContext},
};
use core::{
    ffi::c_void,
    intrinsics::{AtomicOrdering, atomic_xadd},
};
use usbscope_common::*;

#[used]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".usbscope")]
static USBSCOPE_BUILD: BpfBuildInfo = BpfBuildInfo {
    magic: BPF_BUILD_MAGIC,
    architecture: if cfg!(bpf_target_arch = "aarch64") {
        183
    } else {
        62
    },
    config_size: core::mem::size_of::<CaptureConfig>() as u32,
};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024, 0);
#[map]
static CONFIG: Array<CaptureConfig> = Array::with_max_entries(1, 0);
#[map]
static FILTER: Array<KernelPredicate> = Array::with_max_entries(MAX_KERNEL_PREDICATES, 0);
#[map]
static STATS: PerCpuArray<CaptureStats> = PerCpuArray::with_max_entries(1, 0);
#[map]
static SEQUENCE: Array<u64> = Array::with_max_entries(1, 0);
#[map]
static INFLIGHT: HashMap<u64, State> = HashMap::with_max_entries(65536, 1);

#[repr(C)]
#[derive(Clone, Copy)]
struct State {
    id: u64,
    status: i32,
    ready: u32,
}
#[repr(C)]
struct Begin {
    header: RecordHeader,
    meta: EventMeta,
}
#[repr(C)]
struct End {
    header: RecordHeader,
    end: EventEnd,
}
#[repr(C)]
struct Chunk<const N: usize> {
    header: RecordHeader,
    data: [u8; N],
}
#[repr(C)]
struct CopyContext {
    source: u64,
    destination: u64,
    event_id: u64,
    total: u32,
    reason: u32,
    copied: u64,
}

#[repr(C)]
struct IsoRecord {
    header: RecordHeader,
    descriptor: IsoDescriptor,
}

#[repr(C)]
struct IsoContext {
    address: u64,
    copy: CopyContext,
    requested: u32,
    submission: u32,
    data_phase: u32,
    span: u32,
    descriptors: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Default)]
struct SgSegment {
    source: u64,
    next: u64,
    length: u32,
    padding: u32,
}

#[repr(C)]
struct SgContext {
    next: u64,
    // CONFIG is an array map: its value stays valid throughout bpf_loop.
    memory: *const SgMemory,
    copy: *mut CopyContext,
    remaining: u32,
    segment_left: u32,
    segments_left: u32,
    padding: u32,
}

unsafe extern "C" {
    fn core_read_urb(address: u64, meta: *mut EventMeta, buffer: *mut u64, sg: *mut u32) -> i64;
    fn core_completion_status(address: u64, status: *mut i32) -> i64;
    fn core_read_iso(address: u64, index: u32, submission: u32, out: *mut IsoDescriptor) -> i64;
    fn core_sg_start(address: u64, start: *mut u64) -> i64;
    fn core_sg_segment(address: u64, memory: *const SgMemory, out: *mut SgSegment) -> i64;
}

#[inline(always)]
fn next_id() -> u64 {
    SEQUENCE.get_ptr_mut(0).map_or(0, |p| unsafe {
        // LLVM 21 maps relaxed BPF add to XADD without BPF_FETCH, even when
        // its result is used. SeqCst selects the fetch form required for IDs.
        atomic_xadd::<u64, u64, { AtomicOrdering::SeqCst }>(p, 1) + 1
    })
}

#[inline(always)]
fn count(field: usize) {
    if let Some(stats) = STATS.get_ptr_mut(0) {
        unsafe {
            atomic_xadd::<u64, u64, { AtomicOrdering::Relaxed }>(stats.cast::<u64>().add(field), 1);
        }
    }
}

#[inline(always)]
fn header(kind: u16, event_id: u64, size: u32, offset: u64) -> RecordHeader {
    RecordHeader {
        version: ABI_VERSION,
        kind,
        size,
        event_id,
        offset,
    }
}

#[inline(always)]
fn selected(meta: &EventMeta, config: &CaptureConfig) -> bool {
    (config.bus == 0 || config.bus == u32::from(meta.bus))
        && (config.device == u32::MAX || config.device == u32::from(meta.device))
}

#[repr(C)]
struct FilterContext {
    meta: *const EventMeta,
    accepted: u32,
    reserved: u32,
}

#[inline(never)]
fn prefilter(meta: &EventMeta, count: u32) -> bool {
    if count == 0 {
        return true;
    }
    let mut context = FilterContext {
        meta,
        accepted: 1,
        reserved: 0,
    };
    let result = unsafe {
        generated::bpf_loop(
            count.min(MAX_KERNEL_PREDICATES),
            filter_predicate as *mut c_void,
            (&raw mut context).cast(),
            0,
        )
    };
    // Failure must not cause a false negative; exact evaluation is in userspace.
    result < 0 || context.accepted != 0
}

unsafe extern "C" fn filter_predicate(index: u32, context: *mut FilterContext) -> u64 {
    let context = unsafe { &mut *context };
    if let Some(predicate) = FILTER.get(index) {
        if !predicate.matches(unsafe { &*context.meta }) {
            context.accepted = 0;
            return 1;
        }
    }
    0
}

#[fentry]
pub fn observe_submit(ctx: FEntryContext) -> u32 {
    unsafe {
        submit(ctx.arg::<u64>(0));
    }
    0
}

unsafe fn submit(address: u64) {
    let Some(config) = CONFIG.get(0) else {
        return;
    };
    if config.enabled == 0 {
        return;
    }
    let mut meta = EventMeta {
        event_type: b'S',
        ..EventMeta::default()
    };
    let mut buffer = 0;
    let mut sg = 0;
    if unsafe { core_read_urb(address, &mut meta, &mut buffer, &mut sg) } < 0 {
        count(4);
        return;
    }
    if !selected(&meta, config) || !prefilter(&meta, config.filter_count) {
        return;
    }
    let id = next_id();
    if INFLIGHT.get_ptr(address).is_some() {
        count(6);
    }
    if INFLIGHT
        .insert(
            address,
            State {
                id,
                status: 0,
                ready: 0,
            },
            0,
        )
        .is_err()
    {
        count(6);
        return;
    }
    count(0);
    unsafe {
        emit(address, id, b'S', -115);
    }
}

#[fexit]
pub fn observe_submit_error(ctx: FExitContext) -> u32 {
    if let Ok(status) = ctx.ret::<i32>() {
        if status < 0 {
            let address = ctx.arg::<u64>(0);
            if let Some(state) = unsafe { INFLIGHT.get(address).copied() } {
                let _ = INFLIGHT.remove(address);
                count(2);
                unsafe {
                    emit(address, state.id, b'E', status);
                }
            }
        }
    } else {
        count(6);
    }
    0
}

#[fentry]
pub fn observe_giveback(ctx: FEntryContext) -> u32 {
    let address = ctx.arg::<u64>(0);
    if let Some(state) = INFLIGHT.get_ptr_mut(address) {
        let mut status = 0;
        if unsafe { core_completion_status(address, &mut status) } < 0 {
            count(4);
        } else {
            unsafe {
                (*state).status = status;
                (*state).ready = 1;
            }
        }
    }
    0
}

/// A kprobe provides the immediate caller's return address. Accept only the
/// usb_unanchor_urb call from __usb_hcd_giveback_urb, after DMA unmap/copyback.
/// Other unanchor callers (including concurrent cancellation) cannot capture.
#[kprobe]
pub fn observe_complete(ctx: ProbeContext) -> u32 {
    unsafe {
        complete(ctx);
    }
    0
}

unsafe fn complete(ctx: ProbeContext) {
    let Some(config) = CONFIG.get(0) else {
        return;
    };
    #[cfg(bpf_target_arch = "x86_64")]
    let caller =
        unsafe { bpf_probe_read_kernel::<u64>((*ctx.regs).rsp as *const u64) }.unwrap_or(0);
    #[cfg(bpf_target_arch = "aarch64")]
    let caller = unsafe { (*ctx.regs).regs[30] };
    if caller < config.giveback_start || caller >= config.giveback_end {
        return;
    }
    let Some(address) = ctx.arg::<u64>(0) else {
        count(6);
        return;
    };
    let Some(state) = (unsafe { INFLIGHT.get(address).copied() }) else {
        return;
    };
    let _ = INFLIGHT.remove(address);
    if state.ready == 0 {
        count(6);
        return;
    }
    count(1);
    unsafe {
        emit(address, state.id, b'C', state.status);
    }
}

#[inline(never)]
unsafe fn emit(address: u64, urb_id: u64, event_type: u8, status: i32) {
    let Some(config) = CONFIG.get(0) else {
        return;
    };
    let mut meta = EventMeta {
        urb_id,
        event_type,
        timestamp_ns: unsafe { bpf_ktime_get_ns() }.wrapping_add(config.epoch_offset_ns),
        ..EventMeta::default()
    };
    let mut buffer = 0;
    let mut sg = 0;
    if unsafe { core_read_urb(address, &mut meta, &mut buffer, &mut sg) } < 0 {
        count(4);
        return;
    }
    meta.status = status;
    let data_phase = (event_type == b'S' && meta.endpoint & 0x80 == 0)
        || (event_type == b'C' && meta.endpoint & 0x80 != 0);
    let event_id = next_id();
    let mut iso = IsoContext {
        // A no-fault read turns the tracing BTF pointer into an address scalar.
        // Dynamic flexible-array offsets then use only probe_read_kernel,
        // instead of arithmetic on a verifier-tracked typed kernel pointer.
        address: unsafe { bpf_probe_read_kernel(&address as *const u64) }.unwrap_or(0),
        copy: CopyContext {
            source: buffer,
            destination: 0,
            event_id,
            total: 0,
            reason: 0,
            copied: 0,
        },
        requested: meta.requested_len,
        submission: u32::from(event_type == b'S'),
        data_phase: u32::from(data_phase),
        span: 0,
        descriptors: 0,
        reserved: 0,
    };
    if meta.transfer_type == 0 {
        let result = unsafe {
            generated::bpf_loop(
                meta.iso_count,
                iso_measure as *mut c_void,
                (&raw mut iso).cast(),
                0,
            )
        };
        if result < 0 || iso.copy.reason != 0 {
            count(4);
            return;
        }
        if data_phase {
            meta.payload_len = iso.span;
        }
    } else if data_phase {
        meta.payload_len = if event_type == b'S' {
            meta.requested_len
        } else {
            meta.actual_len
        };
    }
    meta.has_data = u8::from(meta.payload_len != 0);
    if meta.payload_len > meta.requested_len || meta.requested_len > i32::MAX as u32 {
        count(4);
        return;
    }
    let Some(mut begin) = EVENTS.reserve::<Begin>(0) else {
        count(3);
        return;
    };
    unsafe {
        begin.as_mut_ptr().write(Begin {
            header: header(RECORD_BEGIN, event_id, 96, 0),
            meta,
        });
    }
    begin.submit(0);
    let mut copy = CopyContext {
        source: buffer,
        destination: 0,
        event_id,
        total: meta.payload_len,
        reason: 0,
        copied: 0,
    };
    let mut descriptors = 0;
    if meta.transfer_type == 0 {
        if meta.payload_len != 0 && (sg != 0 || buffer == 0) {
            iso.copy.reason = LOSS_UNSUPPORTED_BUFFER;
            count(5);
        } else {
            let result = unsafe {
                generated::bpf_loop(
                    meta.iso_count,
                    iso_emit as *mut c_void,
                    (&raw mut iso).cast(),
                    0,
                )
            };
            if result < 0 {
                iso.copy.reason = LOSS_READ;
                count(4);
            }
        }
        copy.reason = iso.copy.reason;
        copy.copied = iso.copy.copied;
        descriptors = iso.descriptors;
    } else if meta.payload_len != 0 {
        if sg != 0 {
            unsafe {
                copy_sg(address, sg, &mut copy);
            }
        } else if buffer == 0 {
            copy.reason = LOSS_UNSUPPORTED_BUFFER;
            count(5);
        } else {
            let iterations =
                (u64::from(meta.payload_len) + CHUNK_SIZE as u64 - 1) / CHUNK_SIZE as u64;
            let result = unsafe {
                generated::bpf_loop(
                    iterations as u32,
                    copy_callback as *mut c_void,
                    (&raw mut copy).cast(),
                    0,
                )
            };
            if result < 0 {
                copy.reason = LOSS_READ;
                count(4);
            }
        }
    }
    let Some(mut end) = EVENTS.reserve::<End>(0) else {
        count(3);
        return;
    };
    unsafe {
        end.as_mut_ptr().write(End {
            header: header(RECORD_END, event_id, 40, 0),
            end: EventEnd {
                copied_bytes: copy.copied,
                descriptors,
                reason: copy.reason,
            },
        });
    }
    end.submit(0);
}

#[inline(always)]
unsafe fn copy_sg(address: u64, segments: u32, copy: &mut CopyContext) {
    count(7);
    let Some(config) = CONFIG.get(0) else {
        copy.reason = LOSS_READ;
        return;
    };
    if config.memory.page_shift == 0 {
        copy.reason = LOSS_UNSUPPORTED_BUFFER;
        count(5);
        return;
    }
    let mut context = SgContext {
        next: 0,
        memory: &config.memory,
        remaining: copy.total,
        copy,
        segment_left: 0,
        segments_left: segments,
        padding: 0,
    };
    if unsafe { core_sg_start(address, &mut context.next) } < 0 {
        copy.reason = LOSS_READ;
        count(4);
        return;
    }
    // At most one extra short chunk per SG entry. This bounds work from the
    // actual URB/SG lengths without imposing a packet snap length.
    let iterations =
        u64::from(segments) + (u64::from(copy.total) + CHUNK_SIZE as u64 - 1) / CHUNK_SIZE as u64;
    if iterations > u64::from(u32::MAX) {
        copy.reason = LOSS_READ;
        count(4);
        return;
    }
    let result = unsafe {
        generated::bpf_loop(
            iterations as u32,
            sg_copy_segment as *mut c_void,
            (&raw mut context).cast(),
            0,
        )
    };
    if result < 0 || (context.remaining != 0 && copy.reason == 0) {
        copy.reason = LOSS_READ;
        count(4);
    }
}

unsafe extern "C" fn sg_copy_segment(_: u32, context: *mut SgContext) -> u64 {
    let context = unsafe { &mut *context };
    if context.remaining == 0 {
        return 1;
    }
    let copy = unsafe { &mut *context.copy };
    if context.segment_left == 0 {
        let mut segment = core::mem::MaybeUninit::<SgSegment>::uninit();
        if context.next == 0
            || context.segments_left == 0
            || unsafe { core_sg_segment(context.next, context.memory, segment.as_mut_ptr()) } < 0
        {
            copy.reason = LOSS_READ;
            count(4);
            return 1;
        }
        // The accessor initializes every field on success.
        let segment = unsafe { segment.assume_init() };
        context.next = segment.next;
        context.segments_left -= 1;
        context.segment_left = segment.length.min(context.remaining);
        copy.source = segment.source;
    }
    let length = context.segment_left.min(CHUNK_SIZE as u32);
    if length == 0 {
        return 0;
    }
    copy.destination = copy.copied;
    copy.reason = unsafe { copy_chunk::<CHUNK_SIZE>(copy, 0, length) };
    if copy.reason != 0 {
        return 1;
    }
    copy.copied += u64::from(length);
    copy.source = copy.source.wrapping_add(u64::from(length));
    context.segment_left -= length;
    context.remaining = context.remaining.saturating_sub(length);
    0
}

unsafe extern "C" fn iso_measure(index: u32, context: *mut IsoContext) -> u64 {
    let context = unsafe { &mut *context };
    let mut descriptor = IsoDescriptor::default();
    if unsafe { core_read_iso(context.address, index, context.submission, &mut descriptor) } < 0 {
        context.copy.reason = LOSS_READ;
        return 1;
    }
    let end = u64::from(descriptor.offset) + u64::from(descriptor.length);
    if end > u64::from(context.requested) {
        context.copy.reason = LOSS_READ;
        return 1;
    }
    if descriptor.length != 0 {
        context.span = context.span.max(end as u32);
    }
    0
}

unsafe extern "C" fn iso_emit(index: u32, context: *mut IsoContext) -> u64 {
    let context = unsafe { &mut *context };
    let mut descriptor = IsoDescriptor::default();
    if unsafe { core_read_iso(context.address, index, context.submission, &mut descriptor) } < 0 {
        context.copy.reason = LOSS_READ;
        count(4);
        return 1;
    }
    let Some(mut record) = EVENTS.reserve::<IsoRecord>(0) else {
        context.copy.reason = LOSS_RING;
        count(3);
        return 1;
    };
    unsafe {
        record.as_mut_ptr().write(IsoRecord {
            header: header(RECORD_ISO, context.copy.event_id, 40, u64::from(index)),
            descriptor,
        });
    }
    record.submit(0);
    context.descriptors += 1;
    if context.data_phase != 0 && descriptor.length != 0 {
        let mut copy = CopyContext {
            source: context
                .copy
                .source
                .wrapping_add(u64::from(descriptor.offset)),
            destination: u64::from(descriptor.offset),
            event_id: context.copy.event_id,
            total: descriptor.length,
            reason: 0,
            copied: 0,
        };
        let iterations = (u64::from(copy.total) + CHUNK_SIZE as u64 - 1) / CHUNK_SIZE as u64;
        let result = unsafe {
            generated::bpf_loop(
                iterations as u32,
                copy_callback as *mut c_void,
                (&raw mut copy).cast(),
                0,
            )
        };
        context.copy.copied += copy.copied;
        context.copy.reason = copy.reason;
        if result < 0 {
            context.copy.reason = LOSS_READ;
            count(4);
        }
        if context.copy.reason != 0 {
            return 1;
        }
    }
    0
}

unsafe extern "C" fn copy_callback(index: u32, context: *mut CopyContext) -> u64 {
    let context = unsafe { &mut *context };
    let offset = u64::from(index) * CHUNK_SIZE as u64;
    if offset >= u64::from(context.total) {
        return 1;
    }
    let length = (u64::from(context.total) - offset).min(CHUNK_SIZE as u64) as u32;
    let reason = unsafe {
        if length <= 256 {
            copy_chunk::<256>(context, offset, length)
        } else if length <= 1024 {
            copy_chunk::<1024>(context, offset, length)
        } else if length <= 4096 {
            copy_chunk::<4096>(context, offset, length)
        } else {
            copy_chunk::<CHUNK_SIZE>(context, offset, length)
        }
    };
    if reason != 0 {
        context.reason = reason;
        return 1;
    }
    context.copied += u64::from(length);
    0
}

#[inline(always)]
unsafe fn copy_chunk<const N: usize>(context: &CopyContext, offset: u64, length: u32) -> u32 {
    if length == 0 || length as usize > N {
        return LOSS_READ;
    }
    let Some(mut chunk) = EVENTS.reserve::<Chunk<N>>(0) else {
        count(3);
        return LOSS_RING;
    };
    let pointer = chunk.as_mut_ptr();
    unsafe {
        (*pointer).header = header(
            RECORD_DATA,
            context.event_id,
            24 + length,
            context.destination + offset,
        );
        let result = generated::bpf_probe_read_kernel(
            (&raw mut (*pointer).data).cast(),
            length,
            context.source.wrapping_add(offset) as *const c_void,
        );
        if result < 0 {
            chunk.discard(0);
            count(4);
            return LOSS_READ;
        }
    }
    // Only header.size bytes are meaningful. The reader omits reservation padding.
    chunk.submit(0);
    0
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
