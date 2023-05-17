
import idc

ops = {
    0x26: (0x26, 'jz(x)', 'x = pop(); if (x == 0) vmPc = pOpcode[vmPc+1];', 2),
    0x2F: (0x2f, 'push_imm()', 'imm = pOpcode[vmPc+1]; push({0});', 2),
    0x31: (0x31, 'xor(x, y)', 'y = pop(); x = pop(); push(x ^ y);', 1),
    0x3B: (0x3b, 'sub(x, y)', 'y = pop(); x = pop(); push(x - y);', 1),
    0x3E: (0x3e, 'shr(x, bit2shift)', 'bit2shift = pop(); x = pop(); push(x >> (uint8_t)bit2shift);', 1),
    0x4F: (0x4f, 'shl(x, bit2shift)', 'bit2shift = pop(); x = pop(); push(x << (uint8_t)bit2shift);', 1),
    0x51: (0x51, 'pop()', 'pop(); just discard the top of the stack;', 1),
    0xD9: (0xd9, 'pop()', 'pop(); just discard the top of the stack;', 1),
    0x52: (0x52, 'mod(x, y)', 'y = pop(); x = pop(); push(x % y);', 1),
    0x68: (0x68, 'greater(x, y)', 'y = pop(); x = pop(); push(x > y);', 1),
    0x7E: (0x7e, 'mul(x, y)', 'y = pop(); x = pop(); push(x * y);', 1),
    0x86: (0x86, 'push_to_idx(x, idx)', 'idx = pop(); x = pop(); vmStack[idx] = x;', 1),
    0x8B: (0x8b, 'call_imm()', 'push(vmPc); imm = pOpcode[vmPc+1]; vmPc = {0};', 2),
    0x9A: (0x9a, 'read_line(start_off)', 'start_off = pop(); scanf("%200s", &vmStack[start_off]);', 1),
    0xAB: (0xab, 'less(x, y)', 'y = pop(); x = pop(); push(x < y);', 1),
    0xB1: (0xb1, 'puts(start_off)', 'start_off = pop(); puts(&vmStack[start_off]);', 1),
    0xC1: (0xc1, 'jmp_imm()', 'imm = pOpcode[vmPc+1]; vmPc = {0};', 2),
    0xC4: (0xc4, 'exit_vm()', 'exit_vm()', 1),
    0xCB: (0xcb, 'jmp(x)', 'x = pop(); vmPc = x;', 1),
    0xD0: (0xd0, 'or(x, y)', 'y = pop(); x = pop(); push(x | y);', 1),
    0xD2: (0xd2, 'dup(x)', 'x = pop(); push(x); push(x);', 1),
    0xD4: (0xd4, 'and(x, y)', 'y = pop(); x = pop(); push(x & y);', 1),
    0xE0: (0xe0, 'div(x, y)', 'y = pop(); x = pop(); push(x / y);', 1),
    0xE2: (0xe2, 'push_from_idx(idx)', 'idx = pop(); pop(); push(vmStack[idx]);', 1),
    0xED: (0xed, 'jnz(x)', 'x = pop(); imm = pOpcodes[vmPc+1]; if (x != 0) vmPc = {0};', 2),
    0xEE: (0xEE, 'is_zero(x)', 'x = pop(); push(x == 0);', 1),
    0xF6: (0xF6, 'equal(x, y)', 'y = pop(); x = pop(); push(x == y);', 1),
    0xF8: (0xF8, 'swap(x, y)', 'y = pop(); x = pop(); push(y); push(x);', 1),
    0xFE: (0xfe, 'add(x, y)', 'y = pop(); x = pop(); push(x + y);', 1),
}


def parse_ops():
    start_ea = 0x4C1100
    ops_count = 2677
    end_ea = start_ea + ops_count * 4
    ea = start_ea
    while ea < end_ea:
        relative_pc = (ea - start_ea) // 4
        op = idc.get_wide_dword(ea)
        if (op in ops):
            op_len = ops[op][3]
            op_desc = ops[op][2]
            if (op_len > 1):
                imm = idc.get_wide_dword(ea + 4)
                op_desc = op_desc.format(imm)
            op_str = f'0x{relative_pc:04x}, {ops[op][1]}, opcode=0x{op:02x}\n\t{op_desc}, vmPc+={op_len}'
            print(op_str)
            ea += 4*ops[op][3]
        else:
            print(f'0x{relative_pc:04x}, opcode=0x{op:02x}, unknown')
            ea += 4

