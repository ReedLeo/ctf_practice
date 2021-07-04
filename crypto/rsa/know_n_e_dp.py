#!/usr/bin/env python3
# coding=utf-8
import gmpy2
import binascii
from Crypto.Util.number import *

# based on the following conditions:
# e*dp - 1 == x*(p-1)
# and 1<= x < e
def get_p_d(n, e, dp):
    prod = e*dp - 1 
    p, d = None, None
    for x in range(1, e):
        if (prod % x):
            continue
        tmp_p = (prod // x) + 1
        if (n % tmp_p):
            continue
        tmp_q = n // tmp_p
        tmp_phi = (tmp_p - 1)*(tmp_q - 1)
        try:
            tmp_d = int(gmpy2.invert(e, tmp_phi))
            p = tmp_p
            d = tmp_d
            break
        except:
            pass
    return p, d

if "__main__" == __name__:
    nbit = 128
    p = getPrime(nbit)
    q = getPrime(nbit)
    n = p*q
    print(f"p={p}\nq={q}\nn={n}")

    phi = (p-1)*(q-1)
    e = 65537
    d = int(gmpy2.invert(e, phi))
    dp = d % (p-1)
    dq = d % (q-1)
    print(f"e={e}\nd={d}\ndp{dp}\ndq={dq}")

    flag = "flag{Demo}"
    m = bytes_to_long(flag.encode())
    print(f"m={m}\n\n")
    # It equivalent:
    # m = int(binascii.b2a_hex(flag.encode()), 16)
    # print(int(binascii.b2a_hex(flag.encode()), 16))

    tmp_p, tmp_d = get_p_d(n, e, dp)
    print(f"tmp_p={tmp_p}\ntmp_d={tmp_d}")
