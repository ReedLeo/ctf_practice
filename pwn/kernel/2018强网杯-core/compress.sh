#!/bin/sh
musl-gcc -o exploit -static $1
mv ./exploit ./initramfs
cd initramfs
find . -print0 \
| cpio --null -ov --format=newc \
| gzip -9 > core.cpio.gz
mv ./core.cpio.gz ../
