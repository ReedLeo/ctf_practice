from ctypes import *
import struct
from hashlib import md5
 
 
def load(file_name):
    with open(file_name, 'rb') as file:
        op_dict = {}
        file.seek(0xf390)
        size = file.read(4)
        size = struct.unpack("I", size)[0]
        file.seek(0x3040)
        bytecode = file.read(size)
        file.seek(0x3020)
        op_code = file.read(12)
        op_dict[op_code[0]] = '='
        op_dict[op_code[1]] = '+='
        op_dict[op_code[2]] = '<<='
        op_dict[op_code[3]] = '>>='
        op_dict[op_code[4]] = '%='
        op_dict[op_code[7]] = '^='
        op_dict['jmp'] = op_code[9]
        op_dict['mov'] = op_code[11]
        return bytecode, op_dict
 
 
def pack2int(a, b, c, d, type):
    return c_int((d << 24) + (c << 16) + (b << 8) + a).value if type else c_uint(
        (d << 24) + (c << 16) + (b << 8) + a).value
 
 
def translate(bytecode, op_dict):
    number_list = []
    bytecode_size = len(bytecode)
    ip = 0
    while ip < bytecode_size:
        # print("{:#x}: ".format(ip), end='')
        op_code = bytecode[ip]
        ip += 1
        if op_code in op_dict:
            # print("reg[{:#x}] {} reg[{:#x}]".format(bytecode[ip], op_dict[op_code], bytecode[ip + 1]))
            ip += 2
        elif op_code == op_dict['jmp']:
            number = pack2int(bytecode[ip], bytecode[ip + 1], bytecode[ip + 2], bytecode[ip + 3], 1)
            ip += 4
            # print("jmp {:#x}".format(ip + number))
            ip = ip + number
        elif op_code == op_dict['mov']:
            number = pack2int(bytecode[ip + 1], bytecode[ip + 2], bytecode[ip + 3], bytecode[ip + 4], 0)
            if number not in [4, 5]:
                number_list.append(number)
            # print("reg[{:#x}] = {:#x}".format(bytecode[ip], number))
            ip += 5
    return number_list
 
 
def decrypt(number_list):
    flag_part2 = number_list.pop()
    flag_part1 = number_list.pop()
    for i in range(128):
        key = number_list.pop()
        flag_part2 -= (((flag_part1 << 4) ^ (flag_part1 >> 5)) + flag_part1) ^ key
        flag_part2 &= 0xffffffff
        key = number_list.pop()
        flag_part1 -= (((flag_part2 << 4) ^ (flag_part2 >> 5)) + flag_part2) ^ key
        flag_part1 &= 0xffffffff
    return flag_part1, flag_part2
 
 
def main():
    filename = "./solve/solve{}.exe"
    flag = b''
    for i in range(100):
        bytecode, op_dict = load(filename.format(i))
        number_list = translate(bytecode, op_dict)
        result = decrypt(number_list)
        flag += result[0].to_bytes(4, byteorder='little') + result[1].to_bytes(4, byteorder='little')
    print(flag)
    print(md5(flag).hexdigest())
 
 
if __name__ == '__main__':
    main()