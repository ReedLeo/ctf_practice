from pwn import *

g_fname = args.FNAME if args.FNAME else "replaced_by_your_file"
g_elf = ELF(g_fname)
context.binary = g_elf
g_libcname = args.LIB if (args.LIB) else "/lib/x86_64-linux-gnu/libc.so.6"

if (args.LOCAL):
	g_io = process(g_fname)
else:
    rhost, rport = args.REMOTE.split(":")
	g_io = remote(rhost, int(rport))

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

