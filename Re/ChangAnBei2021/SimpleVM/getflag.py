import struct
import hashlib
import re

def encrypt(x, y, keys):
    for i in range(128):
        x += ((((y << 4) ^ (y >> 5))+ y) ^ keys[2*i])
        x &= 0xffffffff
        y += ((((x << 4) ^ (x >> 5)) + x) ^ keys[2*i+1])
        y &= 0xffffffff
    return x, y


def decrypt(x, y, keys):
    for i in range(128):
        y -= ((((x << 4) ^ (x >> 5)) + x) ^ keys[2*i])
        y &= 0xffffffff
        x -= ((((y << 4) ^ (y >> 5)) + y) ^ keys[2*i+1])
        x &= 0xffffffff
    print(f'(0x{x:x}, 0x{y:x})')
    return x, y

path_tmpl = './solve/solve{:d}.exe.log'

plains = []

for i in range(100):
    path = path_tmpl.format(i)
    print(f'cur paht: {path}')
    try:
        with open(path, 'r') as f:
            txt = f.read()
    except Exception as e:
        print(f'{i}: open {path} failed.\n except:{e}.')
    res = re.findall(r'regs\[5\] = 0x([0-9a-f]+)', txt)
    keys = [int(x, 16) for x in res[::-1]]
    enc = re.findall(r'regs\[3[0,1]+\] = 0x([0-9a-f]+)', txt)
    enc = [int(x, 16) for x in enc]
    x, y = decrypt(enc[0], enc[1], keys)
    bx = struct.pack('<I', x)
    by = struct.pack('<I', y)
    plains.append(bx+by)

print(f'len of success: {len(plains)}')
res = b''.join(plains)
print(f'plains: {res}')

m = hashlib.md5()
m.update(res)
print(f'flag{m.hexdigest()}')