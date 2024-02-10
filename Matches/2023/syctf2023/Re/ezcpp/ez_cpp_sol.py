import codecs

enc = [0x22, 0xffffffa2, 0x72, 0xffffffe6, 0x52, 0xffffff8c, 0xfffffff2, 0xffffffd4, 0xffffffa6, 0xa, 0x3c, 0x24, 0xffffffa6, 0xffffff9c, 0xffffff86, 0x24, 0x42, 0xffffffd4, 0x22, 0xffffffb6, 0x14, 0x42, 0xffffffce, 0xffffffac, 0x14, 0x6a, 0x2c, 0x7c, 0xffffffe4, 0xffffffe4, 0xffffffe4, 0x1e]

dec = []

for e in enc:
    reverse_bin = bin(e&0xff)[2:].rjust(8, '0')[::-1]
    dec.append(int(reverse_bin, 2))


def decrypt2(e):
    v6 = [0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x1, 0x0, 0x1, 0x0, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1, 0x0, 0x1, 0x0, 0x0, 0x1, 0x1, 0x1, 0x0]
    for i in range(len(e)):
        if i == 16:
            e[i] ^= 4
        elif i < 16:
            if v6[i] == 1:
                e[i] ^= 9
            else:
                e[i] += 2
        else:
            if v6[i] == 1:
                e[i] ^= 6
            else:
                e[i] += 5
    return e

d2 = decrypt2(dec)
print(d2)
print(codecs.decode(''.join(map(chr, d2)), 'rot_13'))
# SYCaY3S-yE5-y0u-S0Ve-Th3-C9P!!!}