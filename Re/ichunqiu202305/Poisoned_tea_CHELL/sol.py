import struct

keys = [0x5, 0x2, 0x9, 0x7]
delta = 0x41104111
enc = [0xecfda301, 0x61becdf5, 0xb89e6c7d, 0xce36dc68, 0x4b6e539e, 0x642eb504, 0x54f9d33c, 0x6d06e365, 0xea873d53, 0xa4618507, 0xd7b18e30, 0xc45b4042]

def encode(a, b):
    v5 = a
    v6 = b
    _sum = 0
    for i in range(0x24):
        v5 += (v6 + ((v6 >> 5) ^ (v6 * 16))) ^ (keys[_sum&3] + _sum)
        v5 &= 0xFFFFFFFF
        _sum -= delta
        _sum &= 0xFFFFFFFF
        v6 += (v5 + ((v5 >> 5) ^ (v5 * 16))) ^ (keys[(_sum >> 11) & 3] + _sum)
        v6 &= 0xFFFFFFFF
    return v5, v6

def decode(a, b):
    v5, v6 = a, b
    _sum = 0xd9b6d99c # == (((-0x41104111) & 0xFFFFFFFF) * 0x24) & 0xFFFFFFFF
    for i in range(0x24):
        v6 -= (v5 + ((v5 >> 5) ^ (v5 * 16))) ^ (keys[(_sum >> 11) & 3] + _sum)
        v6 &= 0xFFFFFFFF
        _sum += delta
        _sum &= 0xFFFFFFFF
        v5 -= (v6 + ((v6 >> 5) ^ (v6 * 16))) ^ (keys[_sum&3] + _sum)
        v5 &= 0xFFFFFFFF
    return v5, v6

for i in range(0, len(enc), 2):
    a, b = enc[i], enc[i+1]
    x, y = decode(a, b)
    print(struct.pack('<I', x).decode(), end="")
    print(struct.pack('<I', y).decode(), end="")
# Thisisflag{cdfec405-3f4b-457e-92fe-f6446098ee2e}