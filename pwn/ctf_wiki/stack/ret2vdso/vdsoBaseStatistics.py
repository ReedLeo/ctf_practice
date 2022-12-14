import os

x32_bases = []
x64_bases = []

x32_min, x32_max = 2**32-1, 0
x64_min, x64_max = 2**64-1, 0

for _ in range(0x200):
    base = int(os.popen("./printVdso32").read().split('@')[1], 16)
    x32_bases.append(base)

    base = int(os.popen("./printVdso64").read().split('@')[1], 16)
    x64_bases.append(base)


def printBases(bases, x32=True):
    if (x32 == True):
        addr_min, addr_max = 2**32-1, 0
        print("vDSO's base in x32 mode:")
    else:
        addr_min, addr_max = 2**64-1, 0
        print("vDSO's base in x64 mode:")
    
    for base in bases:
        addr_min = min(addr_min, base)
        addr_max = max(addr_max, base)
        print("%#x" % base)
    
    print("They are in range[%#x, %#x]\ndiff=%#x" % (addr_min, addr_max, addr_max-addr_min))

printBases(x32_bases)

printBases(x64_bases, False)
