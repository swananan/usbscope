/* SPDX-License-Identifier: MIT OR Apache-2.0 */
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <linux/usbdevice_fs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdint.h>
static int use_sg;

static void save(const char *name, const void *data, size_t length)
{
    char path[128];
    snprintf(path, sizeof(path), "/out/%s", name);
    FILE *file = fopen(path, "wb");
    if (!file || fwrite(data, 1, length, file) != length || fclose(file)) {
        perror(path); exit(1);
    }
}

static void bulk(int fd, unsigned endpoint, void *buffer, unsigned length)
{
    if (use_sg && length >= 65536) {
        struct usbdevfs_urb urb = { .type = USBDEVFS_URB_TYPE_BULK,
            .endpoint = endpoint, .buffer = buffer, .buffer_length = length };
        struct usbdevfs_urb *done = 0;
        if (ioctl(fd, USBDEVFS_SUBMITURB, &urb) || ioctl(fd, USBDEVFS_REAPURB, &done)
            || done != &urb || urb.status || urb.actual_length != (int)length) {
            fprintf(stderr, "async bulk length=%u actual=%d status=%d errno=%d\n", length, urb.actual_length, urb.status, errno);
            exit(1);
        }
        return;
    }
    struct usbdevfs_bulktransfer request = {
        .ep = endpoint, .len = length, .timeout = 5000, .data = buffer,
    };
    int result = ioctl(fd, USBDEVFS_BULK, &request);
    if (result != (int)length) {
        fprintf(stderr, "bulk ep=%02x length=%u result=%d errno=%d\n", endpoint, length, result, errno);
        exit(1);
    }
}

static unsigned char scsi(int fd, unsigned char *cdb, unsigned cdb_len,
                          void *data, unsigned length, int in)
{
    static uint32_t tag;
    unsigned char cbw[31] = {'U', 'S', 'B', 'C'};
    ++tag;
    memcpy(cbw + 4, &tag, 4);
    memcpy(cbw + 8, &length, 4);
    cbw[12] = in ? 0x80 : 0;
    cbw[14] = cdb_len;
    memcpy(cbw + 15, cdb, cdb_len);
    bulk(fd, 2, cbw, sizeof(cbw));
    if (length) bulk(fd, in ? 0x81 : 2, data, length);
    unsigned char csw[13];
    bulk(fd, 0x81, csw, sizeof(csw));
    if (memcmp(csw, "USBS", 4) || memcmp(csw + 4, &tag, 4)) {
        fprintf(stderr, "invalid command status wrapper\n"); exit(1);
    }
    return csw[12];
}

static void storage(int fd)
{
    if (use_sg) {
        unsigned capabilities = 0;
        if (ioctl(fd, USBDEVFS_GET_CAPABILITIES, &capabilities) || !(capabilities & USBDEVFS_CAP_BULK_SCATTER_GATHER)) {
            fprintf(stderr, "test controller does not support SG\n"); exit(1);
        }
    }
    unsigned interface = 0;
    if (ioctl(fd, USBDEVFS_CLAIMINTERFACE, &interface)) { perror("claim"); exit(1); }
    unsigned char ready[6] = {0};
    if (scsi(fd, ready, sizeof(ready), 0, 0, 0)) {
        unsigned char sense[6] = {3, 0, 0, 0, 18, 0}, response[18];
        scsi(fd, sense, sizeof(sense), response, sizeof(response), 1);
        if (scsi(fd, ready, sizeof(ready), 0, 0, 0)) { fprintf(stderr, "disk not ready\n"); exit(1); }
    }
    // One contiguous URB each way, larger than the archive spool threshold.
    enum { LENGTH = 2 * 1024 * 1024 + 512, BLOCKS = LENGTH / 512 };
    unsigned char *out = malloc(LENGTH), *in = malloc(LENGTH);
    if (!out || !in) exit(1);
    for (unsigned i = 0; i < LENGTH; ++i) out[i] = (i * 37 + 11) % 251;
    unsigned char write10[10] = {0x2a, 0, 0, 0, 0, 8, 0, BLOCKS >> 8, BLOCKS & 255, 0};
    unsigned char read10[10];
    memcpy(read10, write10, 10);
    read10[0] = 0x28;
    if (scsi(fd, write10, 10, out, LENGTH, 0) || scsi(fd, read10, 10, in, LENGTH, 1)) {
        fprintf(stderr, "SCSI command failed\n"); exit(1);
    }
    if (memcmp(in, out, LENGTH)) { fprintf(stderr, "USB data mismatch\n"); exit(1); }
    save("bulk.bin", in, LENGTH);
    free(out);
    free(in);
    ioctl(fd, USBDEVFS_RELEASEINTERFACE, &interface);
    printf("USB_BULK_BYTES=%u\n", LENGTH);
}

static unsigned attribute(const char *base, const char *name, unsigned radix)
{
    char path[512], text[64];
    snprintf(path, sizeof(path), "%s/%s", base, name);
    FILE *file = fopen(path, "r");
    if (!file || !fgets(text, sizeof(text), file)) { perror(path); exit(1); }
    fclose(file);
    return strtoul(text, 0, radix);
}

int main(int argc, char **argv)
{
    use_sg = argc == 2 && !strcmp(argv[1], "--sg");
    glob_t devices;
    if (glob("/sys/bus/usb/devices/*/idVendor", 0, 0, &devices)) return 1;
    for (size_t i = 0; i < devices.gl_pathc; i++) {
        char *base = devices.gl_pathv[i];
        *strrchr(base, '/') = 0;
        unsigned dev = attribute(base, "devnum", 10);
        if (dev == 1) continue;
        if (attribute(base, "idProduct", 16) != 1) continue;
        unsigned bus = attribute(base, "busnum", 10);
        char path[128];
        snprintf(path, sizeof(path), "/dev/bus/usb/%03u/%03u", bus, dev);
        int fd = open(path, O_RDWR);
        if (fd < 0) { perror(path); return 1; }
        unsigned char descriptor[18] = {0};
        struct usbdevfs_ctrltransfer request = {
            .bRequestType = 0x80, .bRequest = 6, .wValue = 0x0100,
            .wIndex = 0, .wLength = sizeof(descriptor), .timeout = 2000, .data = descriptor,
        };
        int rc = ioctl(fd, USBDEVFS_CONTROL, &request);
        if (rc != 18) { perror("GET_DESCRIPTOR"); return 1; }
        FILE *expected = fopen("/tmp/probe-expected", "w");
        if (!expected) return 1;
        fprintf(expected, "%u %u %04x %04x 18\n", bus, dev,
                descriptor[8] | descriptor[9] << 8, descriptor[10] | descriptor[11] << 8);
        fclose(expected);
        if (argc == 2 && (!strcmp(argv[1], "--bulk") || use_sg)) {
            save("descriptor.bin", descriptor, sizeof(descriptor));
            storage(fd);
        }
        close(fd);
        globfree(&devices);
        return 0;
    }
    fprintf(stderr, "no USB test device enumerated\n");
    globfree(&devices);
    return 1;
}
