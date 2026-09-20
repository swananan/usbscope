// SPDX-License-Identifier: GPL-2.0
// VM-only fixture: usbfs caps ISO URBs at 128 frames, so use a test driver
// to prove that the capture implementation has no such descriptor limit.
#include <linux/completion.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/usb.h>

#define FRAMES 137
#define STRIDE 224
static int result = -ENODEV;
module_param(result, int, 0444);
static unsigned int actual_lengths[FRAMES];
static int frame_status[FRAMES];
module_param_array(actual_lengths, uint, NULL, 0444);
module_param_array(frame_status, int, NULL, 0444);

static void finished(struct urb *urb)
{
    complete(urb->context);
}

static int test_probe(struct usb_interface *intf, const struct usb_device_id *id)
{
    struct usb_device *dev = interface_to_usbdev(intf);
    DECLARE_COMPLETION_ONSTACK(done);
    struct urb *urb;
    unsigned char *data;
    unsigned i, j, total = 0;
    int rc;
    if (intf->cur_altsetting->desc.bInterfaceNumber != 1)
        return -ENODEV;
    rc = usb_set_interface(dev, 1, 1);
    if (rc) { result = rc; return rc; }
    urb = usb_alloc_urb(FRAMES, GFP_KERNEL);
    data = kmalloc(FRAMES * STRIDE, GFP_KERNEL);
    if (!urb || !data) { rc = -ENOMEM; goto free; }
    memset(data, 0xee, FRAMES * STRIDE);
    urb->dev = dev;
    urb->pipe = usb_sndisocpipe(dev, 1);
    urb->transfer_flags = URB_ISO_ASAP;
    urb->transfer_buffer = data;
    urb->transfer_buffer_length = FRAMES * STRIDE;
    urb->number_of_packets = FRAMES;
    urb->interval = 1;
    urb->context = &done;
    urb->complete = finished;
    for (i = 0; i < FRAMES; i++) {
        unsigned length = i % 3 ? 192 : 188;
        urb->iso_frame_desc[i].offset = i * STRIDE;
        urb->iso_frame_desc[i].length = length;
        for (j = 0; j < length; j++)
            data[i * STRIDE + j] = (i * 13 + j * 7) % 251;
    }
    rc = usb_submit_urb(urb, GFP_KERNEL);
    if (rc) goto free;
    if (!wait_for_completion_timeout(&done, 5 * HZ)) {
        usb_kill_urb(urb);
        rc = -ETIMEDOUT;
        goto free;
    }
    rc = urb->status;
    for (i = 0; i < FRAMES; i++) {
        actual_lengths[i] = urb->iso_frame_desc[i].actual_length;
        frame_status[i] = urb->iso_frame_desc[i].status;
        total += urb->iso_frame_desc[i].actual_length;
        if (!rc && urb->iso_frame_desc[i].status)
            rc = urb->iso_frame_desc[i].status;
    }
    pr_info("USBSCOPE_ISO_DONE frames=%u bytes=%u status=%d\n", FRAMES, total, rc);
free:
    kfree(data);
    usb_free_urb(urb);
    result = rc;
    return rc;
}

static void test_disconnect(struct usb_interface *intf) {}
static const struct usb_device_id ids[] = {
    { USB_DEVICE(0x46f4, 0x0002) }, {}
};
MODULE_DEVICE_TABLE(usb, ids);
static struct usb_driver test_driver = {
    .name = "usbscope-iso-test", .probe = test_probe,
    .disconnect = test_disconnect, .id_table = ids,
};
module_usb_driver(test_driver);
MODULE_LICENSE("GPL");
