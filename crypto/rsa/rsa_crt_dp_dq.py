#!/usr/bin/env python3
# coding=utf-8

#################################################
# This file demonstrates how to accelerate RSA's 
# decryption by intruducing dp and dq
##################################################
import gmpy2
from Crypto.Util.number import *
import logging
import binascii

def encrypt(n, e, m):
    logging.info(f"encryption:\n\tn={n}\n\te={e}\n\tm={m}\n")
    c = pow(m, e, n)    
    return c

def decrypt(n, d, c):
    logging.info(f"n={n}\n\te={e}\n\tc={c}\n")
    m = pow(c, d, n)
    return m

def decrypt_acc(p, q, d, c):
    logging.info(f"decrypt_acc via dp, dq:\n\tp={p}\n\tq={q}\n\td={d}c={c}\n")
    dp = d % (p-1)
    dq = d % (q-1)
    Qinv_p = int(gmpy2.invert(q, p))
    m1 = pow(c, dp, p)
    m2 = pow(c, dq, q)
    n = p*q
    m = (m2 + (m1 - m2)*q*Qinv_p) % n
    return m

if "__main__" == __name__:
    logging.basicConfig(level=logging.INFO)

    flag = "flag{RSA_Acceleration}"
    # m = int(flag.encode().hex(), 16)
    m = bytes_to_long(flag.encode())
    
    nbit = 128
    p = getPrime(nbit)
    q = getPrime(nbit)
    n = p * q
    e = 65537
    phi = (p-1)*(q-1)
    d = int(gmpy2.invert(e, phi))
    
    c = encrypt(n, e, m)
    m1 = decrypt(n, d, c)
    assert(m == m1)
    print("m1: %s" % long_to_bytes(m1).decode())

    m2 = decrypt_acc(p, q, d, c)
    assert(m == m2)
    print("m2: %s" % long_to_bytes(m2).decode())
