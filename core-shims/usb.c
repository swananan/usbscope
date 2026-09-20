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
