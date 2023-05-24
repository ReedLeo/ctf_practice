# uncompyle6 version 3.9.0
# Python bytecode version base 3.8.0 (3413)
# Decompiled from: Python 3.10.4 (main, Mar 24 2022, 13:07:27) [GCC 11.2.0]
# Embedded file name: run.py
import base64, zlib, ctypes
try:
    mylib = ctypes.cdll.LoadLibrary('./mylib.so')
except:
    print('file no exit!')
else:
    a = []
try:
    sstr = input("Please enter the 10 digits and ending with '\\n': ").split(' ')
    if len(sstr) == 10:
        for i in sstr:
            a.append(int(i))

    mylib.check.argtypes = (
     ctypes.POINTER(ctypes.c_int), ctypes.c_int)
    mylib.check.restype = ctypes.c_char_p
    scrambled_code_string = mylib.check((ctypes.c_int * len(a))(*a), len(a))
    try:
        decoded_data = base64.b64decode(scrambled_code_string)
        uncompressed_data = zlib.decompress(decoded_data)
        exec(__import__('marshal').loads(uncompressed_data))
    except:
        print('Incorrect input caused decryption failure!')

except:
    pass