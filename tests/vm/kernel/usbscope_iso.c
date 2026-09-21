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
static bool overlap;
module_param(overlap, bool, 0644);
static bool exercise_errors;
module_param(exercise_errors, bool, 0644);
static int edge_status[4], edge_lengths[4];
module_param_array(edge_status, int, NULL, 0444);
module_param_array(edge_lengths, int, NULL, 0444);
static unsigned char short_data[18];
module_param_array(short_data, byte, NULL, 0444);

static void finished(struct urb *urb)
{
    complete(urb->context);
}

static int test_iso(struct usb_device *dev, bool cancel)
{
    DECLARE_COMPLETION_ONSTACK(done);
    struct urb *urb;
    unsigned char *data;
    unsigned i, j, total = 0;
    int rc;
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
        unsigned offset = (overlap ? i / 2 : i) * STRIDE;
        urb->iso_frame_desc[i].offset = offset;
        urb->iso_frame_desc[i].length = length;
        for (j = 0; j < length; j++)
            data[offset + j] = (i * 13 + j * 7) % 251;
    }
    rc = usb_submit_urb(urb, GFP_KERNEL);
    if (rc) goto free;
    if (cancel) usb_kill_urb(urb);
    if (!wait_for_completion_timeout(&done, 5 * HZ)) {
        usb_kill_urb(urb);
        rc = -ETIMEDOUT;
        goto free;
    }
    rc = urb->status;
    if (cancel) {
        edge_status[3] = rc;
        edge_lengths[3] = urb->actual_length;
    }
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
    return rc;
}

static int test_control(struct usb_device *dev, bool stall)
{
    DECLARE_COMPLETION_ONSTACK(done);
    struct urb *urb = usb_alloc_urb(0, GFP_KERNEL);
    struct usb_ctrlrequest *setup = kzalloc(sizeof(*setup), GFP_KERNEL);
    unsigned char *data = kzalloc(64, GFP_KERNEL);
    int rc = -ENOMEM, index = stall ? 1 : 0;
    if (!urb || !setup || !data) goto free;
    setup->bRequestType = stall ? 0xc0 : USB_DIR_IN;
    setup->bRequest = stall ? 0xff : USB_REQ_GET_DESCRIPTOR;
    setup->wValue = cpu_to_le16(stall ? 0 : USB_DT_DEVICE << 8);
    setup->wLength = cpu_to_le16(64);
    usb_fill_control_urb(urb, dev, usb_rcvctrlpipe(dev, 0), (void *)setup,
                         data, 64, finished, &done);
    if (!stall) urb->transfer_flags = URB_SHORT_NOT_OK;
    rc = usb_submit_urb(urb, GFP_KERNEL);
    if (rc) goto free;
    if (!wait_for_completion_timeout(&done, 5 * HZ)) {
        usb_kill_urb(urb);
        rc = -ETIMEDOUT;
        goto free;
    }
    edge_status[index] = urb->status;
    edge_lengths[index] = urb->actual_length;
    if (!stall) memcpy(short_data, data, sizeof(short_data));
    rc = urb->status == (stall ? -EPIPE : -EREMOTEIO) &&
         urb->actual_length == (stall ? 0 : 18) ? 0 : -EINVAL;
free:
    kfree(data);
    kfree(setup);
    usb_free_urb(urb);
    return rc;
}

static int test_enqueue_error(struct usb_device *dev)
{
    DECLARE_COMPLETION_ONSTACK(done);
    struct urb *urb = usb_alloc_urb(0, GFP_KERNEL);
    int rc;
    if (!urb) return -ENOMEM;
    /* USB core accepts a zero-length interrupt URB, but the real root-hub
     * HCD rejects a status buffer smaller than its port bitmap. This reaches
     * usb_hcd_submit_urb's error return without modifying HCD function pointers. */
    dev = dev->bus->root_hub;
    usb_fill_int_urb(urb, dev, usb_rcvintpipe(dev, 1), NULL, 0, finished, &done, 1);
    rc = usb_submit_urb(urb, GFP_KERNEL);
    edge_status[2] = rc;
    edge_lengths[2] = urb->actual_length;
    if (!rc) usb_kill_urb(urb);
    rc = rc == -EINVAL && !completion_done(&done) ? 0 : -EINVAL;
    usb_free_urb(urb);
    return rc;
}

static int test_probe(struct usb_interface *intf, const struct usb_device_id *id)
{
    struct usb_device *dev = interface_to_usbdev(intf);
    int rc;
    if (intf->cur_altsetting->desc.bInterfaceNumber != 1) return -ENODEV;
    rc = usb_set_interface(dev, 1, 1);
    if (rc) goto done;
    if (exercise_errors) {
        rc = test_control(dev, false);
        if (rc) goto done;
        rc = test_control(dev, true);
        if (rc) goto done;
        rc = test_enqueue_error(dev);
        if (rc) goto done;
        rc = test_iso(dev, true);
        if (rc == -ENOENT) rc = 0;
    } else {
        rc = test_iso(dev, false);
    }
done:
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
