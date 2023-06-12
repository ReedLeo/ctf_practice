import os
import string
import time

fname = '.\\Re\\ez_cpp_org.exe'
table = string.printable
flg = ''
# SYC{Y3S-yE5-y0u-S0Ve-Th3-C9P!!!}
while (len(flg) < 32):
    for ch in table:
        tmp = (flg+ch).ljust(32, '#')
        exitCode = os.system(f'echo {tmp} | {fname} 1>&0')
        if (exitCode == len(flg) + 1):
            flg += ch
            print(flg, exitCode)
            break
    else:
        print('Not found.')
    time.sleep(0.1)
