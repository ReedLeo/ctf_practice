#!/usr/bin/env python3

from pwn import *

def pwn():
    # binary search flag
    

if "__main__" == __name__:
    if (args.DEBUG):
        context.log_level = "debug"
    
    g_fname = args.FNAME if (args.FNAME) else "./chall"
    g_elf = ELF(g_fname)

    pwn()