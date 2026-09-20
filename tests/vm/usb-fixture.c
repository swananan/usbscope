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

static unsigned attribute(const char *base, const char *name, unsigned radix)
{
    char path[512], text[64];
    snprintf(path, sizeof(path), "%s/%s", base, name);
    FILE *file = fopen(path, "r");
    if (!file || !fgets(text, sizeof(text), file)) { perror(path); exit(1); }
    fclose(file);
    return strtoul(text, 0, radix);
}

int main(void)
{
    glob_t devices;
    if (glob("/sys/bus/usb/devices/*/idVendor", 0, 0, &devices)) return 1;
    for (size_t i = 0; i < devices.gl_pathc; i++) {
        char *base = devices.gl_pathv[i];
        *strrchr(base, '/') = 0;
        unsigned dev = attribute(base, "devnum", 10);
        if (dev == 1) continue;
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
        close(fd);
        globfree(&devices);
        return 0;
    }
    fprintf(stderr, "no USB test device enumerated\n");
    globfree(&devices);
    return 1;
}
