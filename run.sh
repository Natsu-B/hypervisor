#!/bin/sh

qemu-system-aarch64 \
  -M virt,gic-version=3,secure=off,virtualization=on \
  -smp 1 -bios /usr/share/qemu-efi-aarch64/QEMU_EFI.fd -cpu cortex-a53 -m 2G \
  -nographic -device virtio-blk-device,drive=disk \
  -drive file=fat:rw:bin/,format=raw,if=none,media=disk,id=disk \
  -cdrom ~/alpine-virt-3.20.2-aarch64.iso \

  #  -cdrom ~/FreeBSD-14.1-RELEASE-arm64-aarch64-RPI.img \
  #  -smp 1 -bios /usr/share/qemu-efi-aarch64/QEMU_EFI.fd -cpu cortex-a53 -m 2G \
  #  -smp 1 -bios QEMU_EFI.fd -cpu cortex-a53 -m 2G \
  #  , dumpdtb=qemu.dtb #dtbを得るための処理