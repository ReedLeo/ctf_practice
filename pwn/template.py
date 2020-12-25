from pwn import *
context(os="linux", arch="i386")

DEBUG = 1
LOCAL = 1

def debug_on():
	context.log_level = "debug"

g_fname = "./babyfengshui"
g_elf = ELF(g_fname)
g_libcname = "./libc-2.19.so"

if (LOCAL):
	g_io = process(g_fname)
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

def pwn():
	pass

if ("__main__" == __name__):
	pwn()
	g_io.interactive()

