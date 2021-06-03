import gmpy2
import libnum

with open("./flag.enc", "rb") as f:
    raw_cipher = f.read()
    print("raw_cipher: ", raw_cipher)
    cipher = libnum.s2n(raw_cipher)

n = 0xC2636AE5C3D8E43FFB97AB09028F1AAC6C0BF6CD3D70EBCA281BFFE97FBE30DD
p = 275127860351348928173285174381581152299 
q = 319576316814478949870590164193048041239
inv_p = int(gmpy2.invert(p, q))
inv_q = int(gmpy2.invert(q, p))
mp = pow(cipher, (p+1)//4, p)
mq = pow(cipher, (q+1)//4, q)
a = (inv_p*p*mq + inv_q*q*mp) % n
b = n - a
c = (inv_p*p*mq - inv_q*q*mp) % n
d = n - c

for i in (a, b, c, d):
    print(libnum.n2s(i))
