#!/bin/sh
./qemu-system-x86_64 \
    -m 512M \
    -kernel ./vmlinuz \
    -initrd  ./core.cpio \
    -L pc-bios \
    -monitor /dev/null \
    -append "root=/dev/ram rdinit=/sbin/init console=ttyS0 oops=panic panic=1 loglevel=7 kaslr" \
    -cpu qemu64,+smep \
    -smp cores=2,threads=1 \
    -device virtsec-device \
    -nographic