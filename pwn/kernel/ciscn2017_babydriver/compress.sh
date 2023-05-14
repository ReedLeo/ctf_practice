#!/bin/sh
musl-gcc -o exploit -static $1
mv ./exploit ./initramfs
cd initramfs
find . -print0 \
| cpio --null -ov --format=newc \
| gzip -9 > rootfs.cpio.gz
mv ./rootfs.cpio.gz ../
