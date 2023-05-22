import ctypes

class inst_info:
    def __init__(self, opcode, name, desc_temp, inst_len, stack_val_num, imm_num):
        self.opcode = opcode
        self.name = name
        self.desc_temp = desc_temp
        self.inst_len = inst_len
        self.stack_val_num = stack_val_num
        self.imm_num = imm_num

ops = {
    0x26: inst_info(0x26, 'jz(x)', 'x = pop() <- 0x{sv1:x}; if (x == 0) vmPc = pOpcode[vmPc+1] = 0x{imm:x};', 2, 1, 1),
    0x2F: inst_info(0x2f, 'push_imm()', 'imm = pOpcodes[vmPc+1] = 0x{imm:x}; push(0x{imm:x});', 2, 0, 1),
    0x31: inst_info(0x31, 'xor(x, y)', 'y = pop() <- 0x{sv1:x}; x = pop() <- 0x{sv2:x}; push(x ^ y);', 1, 2, 0),
    0x3B: inst_info(0x3b, 'sub(x, y)', 'y = pop() <- 0x{sv1:x}; x = pop() <- 0x{sv2:x}; push(x - y);', 1, 2, 0),
    0x3E: inst_info(0x3e, 'shr(x, bit2shift)', 'bit2shift = pop() <- 0x{sv1:x}; x = pop() <- 0x{sv2:x}; push(x >> (uint8_t)bit2shift);', 1, 2, 0),
    0x4F: inst_info(0x4f, 'shl(x, bit2shift)', 'bit2shift = pop() <- 0x{sv1:x}; x = pop() <- 0x{sv2:x}; push(x << (uint8_t)bit2shift);', 1, 2, 0),
    0x51: inst_info(0x51, 'pop()', 'pop() <- 0x{sv1:x}; just discard the top of the stack;', 1, 1, 0),
    0xD9: inst_info(0xd9, 'pop()', 'pop() <- 0x{sv1:x}; just discard the top of the stack;', 1, 1, 0),
    0x52: inst_info(0x52, 'mod(x, y)', 'y = pop() <- 0x{sv1:x}; x = pop() <- 0x{sv2:x}; push(x % y);', 1, 2, 0),
    0x68: inst_info(0x68, 'greater(x, y)', 'y = pop() <- 0x{sv1:x}; x = pop() <- 0x{sv2:x}; push(x > y);', 1, 2, 0),
    0x7E: inst_info(0x7e, 'mul(x, y)', 'y = pop() <- 0x{sv1:x}; x = pop() <- 0x{sv2:x}; push(x * y);', 1, 2, 0),
    0x86: inst_info(0x86, 'push_to_idx(x, idx)', 'idx = pop() <- 0x{sv1:x}; x = pop() <- 0x{sv2:x}; vmStack[idx] = x;', 1, 2, 0),
    0x8B: inst_info(0x8b, 'call_imm()', 'push(vmPc); imm = pOpcodes[vmPc+1] = 0x{imm:x}; vmPc = 0x{imm:x};', 2, 0, 1),
    0x9A: inst_info(0x9a, 'read_line(start_off)', 'start_off = pop() <- 0x{sv1:x}; scanf("%200s", &vmStack[start_off]);', 1, 1, 0),
    0xAB: inst_info(0xab, 'less(x, y)', 'y = pop() <- 0x{sv1:x}; x = pop() <- 0x{sv2:x}; push(x < y);', 1, 2, 0),
    0xB1: inst_info(0xb1, 'puts(start_off)', 'start_off = pop() <- 0x{sv1:x}; puts(&vmStack[start_off]);', 1, 1, 0),
    0xC1: inst_info(0xc1, 'jmp_imm()', 'imm = pOpcodes[vmPc+1] = 0x{imm:x}; vmPc = 0x{imm:x};', 2, 0, 1),
    0xC4: inst_info(0xc4, 'exit_vm()', 'exit_vm()', 1, 0, 0),
    0xCB: inst_info(0xcb, 'jmp(x)', 'x = pop() <- 0x{sv1:x}; vmPc = x;', 1, 1, 0),
    0xD0: inst_info(0xd0, 'or(x, y)', 'y = pop() <- 0x{sv1:x}; x = pop() <- 0x{sv2:x}; push(x | y);', 1, 2, 0),
    0xD2: inst_info(0xd2, 'dup(x)', 'x = pop() <- 0x{sv2:x}; push(x); push(x);', 1, 1, 0),
    0xD4: inst_info(0xd4, 'and(x, y)', 'y = pop() <- 0x{sv1:x}; x = pop() <- 0x{sv2:x}; push(x & y);', 1, 2, 0),
    0xE0: inst_info(0xe0, 'div(x, y)', 'y = pop() <- 0x{sv1:x}; x = pop() <- 0x{sv2:x}; push(x / y);', 1, 2, 0),
    0xE2: inst_info(0xe2, 'push_from_idx(idx)', 'idx = pop() <- 0x{sv1:x}; pop(); push(vmStack[idx]);', 1, 1, 0),
    0xED: inst_info(0xed, 'jnz(x)', 'x = pop() <- 0x{sv1:x}; imm = pOpcodes[vmPc+1] = 0x{imm:x}; if (x != 0) vmPc = 0x{imm:x};', 2, 1, 1),
    0xEE: inst_info(0xEE, 'is_zero(x)', 'x = pop() <- 0x{sv1:x}; push(x == 0);', 1, 1, 0),
    0xF6: inst_info(0xF6, 'equal(x, y)', 'y = pop() <- 0x{sv1:x}; x = pop() <- 0x{sv2:x}; push(x == y);', 1, 2, 0),
    0xF8: inst_info(0xF8, 'swap(x, y)', 'y = pop() <- 0x{sv1:x}; x = pop() <- 0x{sv2:x}; push(y); push(x);', 1, 2, 0),
    0xFE: inst_info(0xfe, 'add(x, y)', 'y = pop() <- 0x{sv1:x}; x = pop() <- 0x{sv2:x}; push(x + y);', 1, 2, 0),
}

rdx = get_reg_value('rdx')
rbx = get_reg_value('rbx')
vmSp = ctypes.c_int32(read_dbg_dword(rbx+0x20)).value
vmPc = read_dbg_dword(rbx+0x1c) - 1
vmStackBase = read_dbg_qword(rbx)
pOpcodes = read_dbg_qword(rbx+0x10)
op = read_dbg_dword(pOpcodes+4*(vmPc))



def get_opcodes(pc, count) -> list:
    opcodes = [0]*count
    for i in range(count):
        opcodes[i] = read_dbg_dword(pOpcodes+4*(pc+i))
    return opcodes

def get_stack_values(sp, count) -> list:
    values = [0]*count
    for i in range(count):
        idx = sp + i
        if (idx < 0):
            continue
        offset = 4 * idx
        values[i] = read_dbg_dword(vmStackBase+offset)
    return values

def print_dbg_info():
    opcodes = get_opcodes(vmPc, 6)
    stkvals = get_stack_values(vmSp-5 , 6)[::-1]
    op_info = ops.get(op, inst_info(0, 'Unknown', 'Unknown opcode',  0, 0, 0 ))
    print(f'0x{vmPc:x}: {op_info.name}, opcode 0x{op:x}')
    print(f'\t{op_info.desc_temp.format(sv1=stkvals[0], sv2=stkvals[1], imm=opcodes[1])}')
    print(f'\tOpcodes@0x{pOpcodes:x}[0x{vmPc:x}:0x{vmPc+6:x}] =','|'.join(map(hex, opcodes)))
    print(f'\tStack@0x{vmStackBase:x}[0x{vmSp:x}:0x{vmSp-6:x}] =', '|'.join(map(hex, stkvals)))
    print()

print_dbg_info()
if( op == 0x9a or op == 0xb1 ):
    return True
else:
    return False