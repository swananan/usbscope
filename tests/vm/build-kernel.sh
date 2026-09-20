#!/bin/sh
set -eu
source_dir=$(realpath "${1:?usage: build-kernel.sh LINUX_SOURCE [BUILD_DIR]}")
build_dir=$(realpath -m "${2:-target/vm-kernel}")
mkdir -p "$build_dir"
make -s -C "$source_dir" O="$build_dir" allnoconfig
config="$source_dir/scripts/config"
for feature in 64BIT SMP PRINTK BUG ELF_CORE BINFMT_ELF BINFMT_SCRIPT MULTIUSER \
    NET UNIX PCI PCI_MSI ACPI MODULES BPF BPF_SYSCALL BPF_JIT BPF_JIT_ALWAYS_ON \
    VIRTIO_MENU VIRTIO VIRTIO_PCI NET_9P NET_9P_VIRTIO 9P_FS \
    RELOCATABLE RANDOMIZE_BASE RANDOMIZE_MEMORY \
    KALLSYMS KALLSYMS_ALL KPROBES PERF_EVENTS FTRACE FUNCTION_TRACER \
    DYNAMIC_FTRACE DYNAMIC_FTRACE_WITH_REGS KPROBE_EVENTS BPF_EVENTS \
    DEBUG_KERNEL DEBUG_INFO_DWARF4 DEBUG_INFO_BTF \
    BLK_DEV_INITRD RD_GZIP DEVTMPFS DEVTMPFS_MOUNT \
    TTY SERIAL_8250 SERIAL_8250_CONSOLE PROC_FS SYSFS TMPFS SHMEM \
    FUTEX EPOLL SIGNALFD TIMERFD EVENTFD POSIX_TIMERS \
    USB_SUPPORT USB USB_XHCI_HCD USB_XHCI_PCI USB_EHCI_HCD USB_EHCI_PCI \
    USB_ANNOUNCE_NEW_DEVICES IKCONFIG IKCONFIG_PROC; do
    "$config" --file "$build_dir/.config" --enable "$feature"
done
"$config" --file "$build_dir/.config" --disable USB_MON --set-val NR_CPUS 8
make -s -C "$source_dir" O="$build_dir" olddefconfig
for feature in BPF_SYSCALL BPF_JIT DEBUG_INFO_BTF KPROBES DYNAMIC_FTRACE USB IKCONFIG_PROC NET_9P_VIRTIO; do
    if ! grep -q "^CONFIG_${feature}=y$" "$build_dir/.config"; then
        printf 'Required kernel feature was not enabled: CONFIG_%s\n' "$feature" >&2
        exit 1
    fi
done
grep -q '^# CONFIG_USB_MON is not set$' "$build_dir/.config"
make -s -C "$source_dir" O="$build_dir" -j "${JOBS:-8}" bzImage
printf 'Kernel: %s/arch/x86/boot/bzImage\n' "$build_dir"
