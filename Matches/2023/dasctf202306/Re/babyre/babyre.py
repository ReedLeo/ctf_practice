import subprocess
v4 = [0]*44
v4[0] = 0xF7
v4[1] = 0x2E
v4[2] = 0x34
v4[3] = 0xF0
v4[4] = 0x72
v4[5] = 0xCF
v4[6] = 0x5E
v4[7] = 0xA
v4[8] = 0xBB
v4[9] = 0xEC
v4[10] = 0xB1
v4[11] = 0x2B
v4[12] = 0x70
v4[13] = 0x88
v4[14] = 0x88
v4[15] = 0xED
v4[16] = 0x46
v4[17] = 0x38
v4[18] = 0xDB
v4[19] = 0xDA
v4[20] = 0x6C
v4[21] = 0xBD
v4[22] = 0xD4
v4[23] = 6
v4[24] = 0x77
v4[25] = 0xF2
v4[26] = 0xCF
v4[27] = 0x56
v4[28] = 0x88
v4[29] = 0xC6
v4[30] = 0x31
v4[31] = 0xD2
v4[32] = 0xB7
v4[33] = 0x5A
v4[34] = 0xC1
v4[35] = 0x42
v4[36] = 0xB0
v4[37] = 0xF4
v4[38] = 0x48
v4[39] = 0x37
v4[40] = 0xF5
v4[41] = 0x2C
v4[42] = 0xF5
v4[43] = 0x58

def encode(usr_input):
    keys = [0x5d, 0x42, 0x62, 0x29, 3, 0x36, 0x47, 0x41, 0x15, 0x36]
    keys_len = len(keys)
    s = 0 
    v5 = [i for i in range(0x100)]
    for i in range(0x100):
        s = (s * 2 + v5[i] + keys[i%keys_len]) & 0xff
        tmp = v5[i]
        v5[i] = v5[s]
        v5[s] = tmp

    s = 0
    ki = 0
    for i in range(len(usr_input)):
        s = (ki + s) & 0xff
        ki = (v5[s] + ki) & 0xff
        tmp = v5[s]
        v5[s] = v5[ki]
        v5[ki] = tmp
        v13 = v5[(v5[s] + ki + v5[ki]) & 0xff]
        usr_input[i] ^= v13
        usr_input[i] += i % 13
    return usr_input

def decode(usr_input):
    keys = [0x5d, 0x42, 0x62, 0x29, 3, 0x36, 0x47, 0x41, 0x15, 0x36]
    keys_len = len(keys)
    s = 0 
    v5 = [i for i in range(0x100)]
    for i in range(0x100):
        s = (s * 2 + v5[i] + keys[i%keys_len]) & 0xff
        tmp = v5[i]
        v5[i] = v5[s]
        v5[s] = tmp

    s = 0
    ki = 0
    for i in range(len(usr_input)):
        s = (ki + s) & 0xff
        ki = (v5[s] + ki) & 0xff
        tmp = v5[s]
        v5[s] = v5[ki]
        v5[ki] = tmp
        usr_input[i] -= i % 13
        usr_input[i] &= 0xff
        v13 = v5[(v5[s] + ki + v5[ki]) & 0xff]
        usr_input[i] ^= v13
    return usr_input

flg = decode(v4)
print(''.join(map(chr, flg)))


