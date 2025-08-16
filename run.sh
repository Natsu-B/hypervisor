#!/bin/sh

./build.sh
if [ $? -eq 0 ]; then
  echo "success to build"
else
  echo "failed to build"
  exit 1
fi

ALPINE_ISO=~/alpine-virt-3.22.1-aarch64.iso

if [ ! -f "$ALPINE_ISO" ]; then
    echo "Error: Alpine ISO image not found at $ALPINE_ISO"
    echo "Please download it from https://alpinelinux.org/downloads/"
    echo "Ensure the version is 3.20.2 and the architecture is aarch64 (virt)."
    exit 1
fi

qemu-system-aarch64 \
  -M virt,gic-version=3,secure=off,virtualization=on \
  -smp 4 -bios QEMU_EFI.fd -cpu cortex-a53 -m 2G \
  -nographic -device virtio-blk-device,drive=disk \
  -drive file=fat:rw:bin/,format=raw,if=none,media=disk,id=disk \
  -cdrom "$ALPINE_ISO" \
  -gdb tcp::1234 #-S

  #  -cdrom ~/FreeBSD-14.1-RELEASE-arm64-aarch64-RPI.img \
  #  -smp 1 -bios /usr/share/qemu-efi-aarch64/QEMU_EFI.fd -cpu cortex-a53 -m 2G \
  #  -smp 1 -bios QEMU_EFI.fd -cpu cortex-a53 -m 2G \
  #  , dumpdtb=qemu.dtb #dtbを得るための処理
