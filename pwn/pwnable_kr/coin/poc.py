from pwn import *
# context.log_level = "debug"
io = remote("pwnable.kr", 9007)

io.recvuntil(b"Ready? starting in 3 sec...")
for i in range(100):
    log.info(str(i))
    io.recvuntil(b"N=")
    N=int(io.recvuntil(b" C=", drop=True))
    C=int(io.recvline())
    l, r = 0, N
    for j in range(C):  # must loop C times.
        log.debug("in range [%d, %d)" % (l, r))
        m = (l + r) // 2
        lc = ' '.join(map(str, [x for x in range(l, m)])).encode()
        # rc = ' '.join(map(str, [x for x in range(m, r)])).encode()
        if (len(lc) > 0):
            io.sendline(lc)
            weight = int(io.recvline())
            log.debug("weight=%d" % weight)
            if (weight % 10 == 0):
                l = m
            else:
                r = m
        else:
            # lc is empty so len(rc) == 1, l is the answer.
            io.sendline(str(l).encode())
    io.sendline(str(l).encode())

io.interactive()