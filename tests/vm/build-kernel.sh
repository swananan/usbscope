#!/bin/sh
set -eu
source_dir=$(realpath "${1:?usage: build-kernel.sh LINUX_SOURCE [BUILD_DIR]}")
build_dir=$(realpath -m "${2:-target/vm-kernel}")
case "${ARCH:-$(uname -m)}" in
    x86|x86_64) ARCH=x86; image=bzImage; image_path=arch/x86/boot/bzImage ;;
    arm64|aarch64)
        ARCH=arm64; image=Image; image_path=arch/arm64/boot/Image
        if [ "$(uname -m)" != aarch64 ]; then
            CROSS_COMPILE=${CROSS_COMPILE:-aarch64-linux-gnu-}
            export CROSS_COMPILE
        fi
        ;;
    *) printf 'Unsupported kernel architecture\n' >&2; exit 1 ;;
esac
export ARCH
mkdir -p "$build_dir"
make -s -C "$source_dir" O="$build_dir" allnoconfig
config="$source_dir/scripts/config"
for feature in 64BIT SMP PRINTK BUG ELF_CORE BINFMT_ELF BINFMT_SCRIPT MULTIUSER \
    NET UNIX PCI PCI_MSI ACPI MODULES BPF BPF_SYSCALL BPF_JIT BPF_JIT_ALWAYS_ON \
    VIRTIO_MENU VIRTIO VIRTIO_PCI NET_9P NET_9P_VIRTIO 9P_FS \
    RELOCATABLE RANDOMIZE_BASE RANDOMIZE_MEMORY \
    KALLSYMS KALLSYMS_ALL KPROBES PERF_EVENTS FTRACE FUNCTION_TRACER \
    DYNAMIC_FTRACE DYNAMIC_FTRACE_WITH_REGS KPROBE_EVENTS BPF_EVENTS \
    DYNAMIC_FTRACE_WITH_ARGS DYNAMIC_FTRACE_WITH_CALL_OPS DYNAMIC_FTRACE_WITH_DIRECT_CALLS \
    DEBUG_KERNEL DEBUG_INFO_DWARF4 DEBUG_INFO_BTF \
    BLK_DEV_INITRD RD_GZIP DEVTMPFS DEVTMPFS_MOUNT \
    TTY SERIAL_8250 SERIAL_8250_CONSOLE PROC_FS SYSFS TMPFS SHMEM \
    FUTEX EPOLL SIGNALFD TIMERFD EVENTFD POSIX_TIMERS \
    USB_SUPPORT USB USB_XHCI_HCD USB_XHCI_PCI USB_EHCI_HCD USB_EHCI_PCI \
    USB_ANNOUNCE_NEW_DEVICES IKCONFIG IKCONFIG_PROC; do
    "$config" --file "$build_dir/.config" --enable "$feature"
done
if [ "$ARCH" = arm64 ]; then
    for feature in OF ARM_AMBA ARM_GIC ARM_GIC_V3 ARM_ARCH_TIMER PCI_HOST_GENERIC \
        SERIAL_AMBA_PL011 SERIAL_AMBA_PL011_CONSOLE VIRTIO_MMIO; do
        "$config" --file "$build_dir/.config" --enable "$feature"
    done
    case "${ARM64_PAGE_SIZE:-4K}" in
        4K|16K|64K) ;;
        *) printf 'ARM64_PAGE_SIZE must be 4K, 16K, or 64K\n' >&2; exit 1 ;;
    esac
    "$config" --file "$build_dir/.config" --enable "ARM64_${ARM64_PAGE_SIZE:-4K}_PAGES"
    "$config" --file "$build_dir/.config" --enable ARM64_VA_BITS_48
fi
case "${USBMON:-n}" in
    y) "$config" --file "$build_dir/.config" --enable USB_MON ;;
    n) "$config" --file "$build_dir/.config" --disable USB_MON ;;
    *) printf 'USBMON must be y or n (default n)\n' >&2; exit 1 ;;
esac
"$config" --file "$build_dir/.config" --set-val NR_CPUS 8
make -s -C "$source_dir" O="$build_dir" olddefconfig
for feature in BPF_SYSCALL BPF_JIT DEBUG_INFO_BTF KPROBES DYNAMIC_FTRACE USB IKCONFIG_PROC NET_9P_VIRTIO; do
    if ! grep -q "^CONFIG_${feature}=y$" "$build_dir/.config"; then
        printf 'Required kernel feature was not enabled: CONFIG_%s\n' "$feature" >&2
        exit 1
    fi
done
if [ "${USBMON:-n}" = y ]; then
    grep -q '^CONFIG_USB_MON=y$' "$build_dir/.config"
else
    grep -q '^# CONFIG_USB_MON is not set$' "$build_dir/.config"
fi
make -s -C "$source_dir" O="$build_dir" -j "${JOBS:-8}" "$image"
printf 'Kernel: %s/%s\n' "$build_dir" "$image_path"
