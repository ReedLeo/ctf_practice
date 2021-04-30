import libnum
import gmpy2

# n, e are extracted from pubke.pem file via openssl
n = 0xC2636AE5C3D8E43FFB97AB09028F1AAC6C0BF6CD3D70EBCA281BFFE97FBE30DD
e = 65537
# factorized by Yafu
p = 275127860351348928173285174381581152299
q = 319576316814478949870590164193048041239

phi = (p-1)*(q-1)

d = int(gmpy2.invert(e, phi))

with open("./flag.enc", "rb") as f:
	c = libnum.s2n(f.read())

m = libnum.n2s(int(gmpy2.powmod(c, d, n)))
print(m)
# PCTF{256b_i5_m3dium}
