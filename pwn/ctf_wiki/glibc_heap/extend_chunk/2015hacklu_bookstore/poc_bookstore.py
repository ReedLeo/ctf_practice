from pwn import *
context(os="linux", arch="amd64")

DEBUG = 1
LOCAL = 1

def debug_on():
	context.log_level = "debug"

g_fname = "./books"
g_elf = ELF(g_fname)
g_libcname = "/glibc/2.23/64/lib/libc-2.23.so" if LOCAL else "./libc-2.23.so"
ld_name = "/glibc/2.23/64/lib/ld-2.23.so"

if (LOCAL):
	g_io = process([ld_name, g_fname])
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
	

def pwn():
	pass

if ("__main__" == __name__):
	debug_on()
	pwn()
	g_io.interactive()

