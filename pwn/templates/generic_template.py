from pwn import *

g_fname = args.FNAME 
g_elf = ELF(g_fname)
g_libcname = args.LIB if (args.LIB) else "/lib/x86_x64-linux-gnu/libc.so.6"

if (LOCAL):
	g_io = process(g_fname)
else:
	g_io = remote()

g_libc = ELF(g_libcname)

def getpid():
	if (args.LOCAL):
		log.info("PID: %d", g_io.proc.pid)
		pause()

s, sa, sl, sla = g_io.send, g_io.sendafter, g_io.sendline, g_io.sendlineafter
r, ru, rl = g_io.recv, g_io.recvuntil, g_io.recvline

def pwn():
	pass

if ("__main__" == __name__):
	if (args.DEBUG):
		context.log_level = "debug"
	pwn()
	g_io.interactive()

