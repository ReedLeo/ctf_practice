from z3 import *

enc = [0x36d3, 0x2aff, 0x2acb, 0x2b95, 0x2b95, 0x2b95, 0x169f, 0x186d, 0x18d7, 0x1611, 0x18d7, 0x2b95, 0x2c23, 0x2ca9, 0x1611, 0x1611, 0x18d7, 0x2aff, 0x1849, 0x18fb, 0x2acb, 0x2a71, 0x1735, 0x18d7, 0x1611, 0x2acb, 0x15dd, 0x18d7, 0x2c23, 0x169f, 0x15dd, 0x2b95, 0x169f, 0x156b, 0x186d, 0x2aff, 0x1611, 0x1611, 0x15dd, 0x2aff, 0x2c23, 0x2acb, 0x15dd, 0x15dd, 0x186d, 0x1849, 0x2b95, 0x156b, 0x1735, 0x18fb, 0x18fb, 0x2a71, 0x2aff, 0x1735, 0x2c23, 0x15dd, 0x18d7, 0x2a71, 0x18d7, 0x18d7, 0x2c23, 0x2aff, 0x156b, 0x2c23, 0x169f, 0x35af, 0x2ca9, 0x32b5, 0x2aff, 0x3039, 0x0, 0x0]
enc = enc[::-1]
flg = ''
for i in range(len(enc)):
    s = Solver()
    x = BitVec('x', 32)
    s.add(x>0, x<127)
    s.add(((x*0x6e + 0x63)^0x74)+0x66 == enc[i])
    if (s.check() == sat):
        m = s.model()
        flg += chr(m[x].as_long())
    else:
        print(f'{i}: not found')

# for i in range(72):
#     x = (((((enc[i] - 0x66)^0x74)-0x63)&0xffffffff)//0x6e)&0xff
#     flg += chr(x)

print(flg)
