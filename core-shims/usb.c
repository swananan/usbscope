/* SPDX-License-Identifier: MIT OR Apache-2.0
 * Only kernel structure access belongs here. Capture policy stays in Rust.
 * These minimal type views intentionally differ from actual kernel layouts;
 * Clang emits CO-RE field relocations for every READ operation.
 */
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef int i32;

#define CORE __attribute__((preserve_access_index))
struct usb_bus { int busnum; } CORE;
struct usb_device_descriptor { u16 idVendor; u16 idProduct; } CORE;
struct usb_device {
    int devnum;
    struct usb_bus *bus;
    struct usb_device_descriptor descriptor;
} CORE;
struct usb_endpoint_descriptor { u8 bEndpointAddress; u8 bmAttributes; } CORE;
struct usb_host_endpoint { struct usb_endpoint_descriptor desc; } CORE;
struct usb_iso_packet_descriptor { u32 offset; u32 length; u32 actual_length; i32 status; } CORE;
struct page { u64 flags; } CORE;
struct scatterlist { u64 page_link; u32 offset, length; } CORE;
struct urb {
    struct usb_device *dev;
    struct usb_host_endpoint *ep;
    i32 status;
    i32 unlinked;
    u32 transfer_flags;
    void *transfer_buffer;
    u32 transfer_buffer_length;
    u32 actual_length;
    u8 *setup_packet;
    i32 start_frame;
    i32 number_of_packets;
    i32 interval;
    i32 error_count;
    i32 num_sgs;
    struct scatterlist *sg;
    struct usb_iso_packet_descriptor iso_frame_desc[];
} CORE;

struct event_meta {
    u64 urb_id, timestamp_ns;
    u16 bus;
    u8 device, endpoint, transfer_type, event_type, setup_present, has_data;
    i32 status;
    u32 requested_len, actual_len, payload_len;
    i32 interval, start_frame;
    u32 transfer_flags, iso_count;
    i32 error_count;
    u16 vid, pid;
    u8 setup[8];
};
_Static_assert(sizeof(struct event_meta) == 72, "Rust/C metadata ABI mismatch");
static long (*probe_read)(void *, u32, const void *) = (void *)113;

#define READ(destination, source) do { \
    if (probe_read(&(destination), sizeof(destination), \
        __builtin_preserve_access_index(&(source))) < 0) return -1; \
} while (0)

long core_read_urb(u64 address, struct event_meta *m, u64 *buffer, u32 *sg_count)
{
    struct urb *urb = (void *)address;
    struct usb_device *dev = 0;
    struct usb_bus *bus = 0;
    struct usb_host_endpoint *ep = 0;
    int busnum = 0, devnum = 0, packets = 0, sgs = 0;
    u8 attributes = 0, epnum = 0;
    void *data = 0;
    READ(dev, urb->dev);
    READ(bus, dev->bus);
    READ(busnum, bus->busnum);
    READ(devnum, dev->devnum);
    READ(m->vid, dev->descriptor.idVendor);
    READ(m->pid, dev->descriptor.idProduct);
    READ(ep, urb->ep);
    READ(attributes, ep->desc.bmAttributes);
    READ(epnum, ep->desc.bEndpointAddress);
    READ(m->transfer_flags, urb->transfer_flags);
    READ(m->requested_len, urb->transfer_buffer_length);
    READ(m->actual_len, urb->actual_length);
    READ(m->interval, urb->interval);
    READ(m->start_frame, urb->start_frame);
    READ(m->error_count, urb->error_count);
    READ(m->status, urb->status);
    READ(packets, urb->number_of_packets);
    READ(data, urb->transfer_buffer);
    READ(sgs, urb->num_sgs);
    m->bus = busnum;
    m->device = devnum;
    m->endpoint = (epnum & 0x0f) | ((m->transfer_flags & 0x0200) ? 0x80 : 0);
    switch (attributes & 3) {
        case 0: m->transfer_type = 2; break;
        case 1: m->transfer_type = 0; break;
        case 2: m->transfer_type = 3; break;
        default: m->transfer_type = 1; break;
    }
    if (m->transfer_type == 0 && packets < 0) return -1;
    m->iso_count = m->transfer_type == 0 ? packets : 0;
    if (m->transfer_type == 2 && m->event_type == 'S') {
        u8 *setup = 0;
        READ(setup, urb->setup_packet);
        if (probe_read(m->setup, 8, setup) < 0) return -1;
        m->setup_present = 1;
    }
    *buffer = (u64)data;
    *sg_count = sgs;
    return 0;
}

long core_completion_status(u64 address, i32 *status)
{
    struct urb *urb = (void *)address;
    u32 flags = 0, actual = 0, requested = 0;
    READ(*status, urb->unlinked);
    READ(flags, urb->transfer_flags);
    READ(actual, urb->actual_length);
    READ(requested, urb->transfer_buffer_length);
    if (!*status && (flags & 1) && actual < requested) *status = -121;
    return 0;
}

struct iso_descriptor { i32 status; u32 offset, length, padding; };

long core_read_iso(u64 address, u32 index, u32 submission, struct iso_descriptor *out)
{
    struct urb *urb = (void *)address;
    /* Relocate the flexible-array field, without indexing its zero-size BTF
     * array. Aya correctly rejects an element index in a zero-size array. */
    u32 offset = __builtin_preserve_field_info(urb->iso_frame_desc, 0);
    struct usb_iso_packet_descriptor *first = (void *)(address + offset);
    u32 size = __builtin_preserve_type_info(*(struct usb_iso_packet_descriptor *)0, 1);
    struct usb_iso_packet_descriptor *desc = (void *)((u8 *)first + (u64)index * size);
    READ(out->offset, desc->offset);
    READ(out->status, desc->status);
    if (submission) READ(out->length, desc->length);
    else READ(out->length, desc->actual_length);
    out->padding = 0;
    return 0;
}

struct sg_segment { u64 source, next; u32 length, padding; };

long core_sg_start(u64 address, u64 *start)
{
    struct urb *urb = (void *)address;
    struct scatterlist *sg = 0;
    READ(sg, urb->sg);
    *start = (u64)sg;
    return 0;
}

struct sg_memory { u64 vmemmap_symbol, page_offset_symbol; u32 page_shift, va_bits, layout, padding; };
_Static_assert(sizeof(struct sg_memory) == 32, "Rust/C SG configuration ABI mismatch");

/* SPARSEMEM_VMEMMAP CPU virtual addresses, never DMA-address translation.
 * x86_64 obtains the mapping bases from runtime kernel variables.
 * arm64 derives PAGE_OFFSET and VMEMMAP_START from the running configuration
 * and CO-RE sizeof(struct page), as in arch/arm64/include/asm/memory.h. */
long core_sg_segment(u64 address, const struct sg_memory *memory, struct sg_segment *out)
{
    struct scatterlist *sg = (void *)address;
    u64 link = 0, vmemmap = 0, direct = 0;
    u32 offset = 0;
    READ(link, sg->page_link);
    READ(offset, sg->offset);
    READ(out->length, sg->length);
    if ((link & 1) || !link) return -1;
    u64 page = link & ~3ULL;
    u32 page_size = __builtin_preserve_type_info(*(struct page *)0, 1);
    u32 shift = memory->page_shift;
    u64 max_pages;
#if defined(USBSCOPE_ARM64)
    u32 bits = memory->va_bits;
    if ((shift != 12 && shift != 14 && shift != 16) || bits < 36 || bits > 52) return -1;
    if (!page_size || page_size > 4096) return -1;
    direct = 0ULL - (1ULL << bits);
    u32 min_bits = bits > 48 ? (shift == 14 ? 47 : 48) : bits;
    u64 end = 0ULL - (1ULL << (min_bits - 1));
    max_pages = (end - direct) >> shift;
    if (memory->layout == 1) { /* SG_ARM64_LEGACY: upstream before 6.9 */
        u32 order = 0;
        /* Kernel STRUCT_PAGE_MAX_SHIFT is ceil(log2(sizeof(struct page))). */
        for (; order < 12; order++) {
            if ((1U << order) >= page_size) break;
        }
        if (order >= shift) return -1;
        vmemmap = 0ULL - (1ULL << (bits - shift + order));
    } else if (memory->layout == 2) { /* SG_ARM64_COMPACT: upstream 6.9+ */
        vmemmap = (0ULL - (1ULL << 30)) - max_pages * page_size;
    } else {
        return -1;
    }
#elif defined(USBSCOPE_X86_64)
    if (shift != 12 || !memory->vmemmap_symbol || !memory->page_offset_symbol) return -1;
    if (probe_read(&vmemmap, 8, (void *)memory->vmemmap_symbol) < 0 ||
        probe_read(&direct, 8, (void *)memory->page_offset_symbol) < 0) return -1;
    max_pages = 1ULL << 40; /* x86 physical addresses are <=52 bits */
#else
#error Unsupported SG architecture
#endif
    if (!vmemmap || !direct || !page_size || page < vmemmap ||
        (page - vmemmap) % page_size) return -1;
    u64 pfn = (page - vmemmap) / page_size;
    if (pfn >= max_pages) return -1;
    out->source = direct + (pfn << shift) + offset;
    out->next = 0;
    out->padding = 0;
    if (!(link & 2)) {
        u32 stride = __builtin_preserve_type_info(*(struct scatterlist *)0, 1);
        struct scatterlist *next = (void *)(address + stride);
        READ(link, next->page_link);
        out->next = link & 1 ? link & ~3ULL : (u64)next;
    }
    return 0;
}
