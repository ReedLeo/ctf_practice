from pwn import *
import sys

def parse_ops(exe):

    op_idxs = [0,1,2,3,4,7,9,11]
    ops = [u8(exe.read(exe.symbols['opcodes']+x, 1)) for x in op_idxs]
    log.info(f'valid ops:{ops}')

    op_mp = {
        ops[0]: ('mov_regs', 'regs[{0}] = regs[{1}]', 3),
        ops[1]: ('add_regs', 'regs[{0}] += regs[{1}]', 3),
        ops[2]: ('shl_regs', 'regs[{0}] <<= regs[{1}]', 3),
        ops[3]: ('shr_regs', 'regs[{0}] >>= regs[{1}]', 3),
        ops[4]: ('mod_regs', 'regs[{0}] %= regs[{1}]', 3),
        ops[5]: ('xor_regs', 'regs[{0}] ^= regs[{1}]', 3),
        ops[6]: ('jmp_imm', 'pc += 0x{0:x}', 5),
        ops[7]: ('mov_imm', 'regs[{0}] = 0x{1:x}', 6),
    }

    op_start = exe.symbols['bytecode']
    op_count = u32(exe.read(exe.symbols['bytecodeSize'], 4))
    all_ins = exe.read(op_start, op_count)

    vmPc = 0
    max_reg_idx = 0
    while (vmPc < op_count):
        op = all_ins[vmPc]
        if (op in op_mp):
            r1 = all_ins[vmPc + 1]
            r2 = 0
            ins_len = op_mp[op][2]
            desc_str = op_mp[op][1]
            op_str = 'Unknown'
            if (ins_len == 3):
                r2 = all_ins[vmPc+2]
                op_str = desc_str.format(r1, r2)
            elif (ins_len == 5):
                imm = u32(all_ins[vmPc+1: vmPc+5])
                op_str = desc_str.format(imm)
                vmPc += imm # jmp to where offsets imm bytes from just after current instruction
            elif (ins_len == 6):
                imm = u32(all_ins[vmPc+2: vmPc+6])
                op_str = desc_str.format(r1, imm)
            vmPc += ins_len
            print(f'0x{vmPc:04x}: {op_mp[op][0]}:\n\t{op_str}, opcode= 0x{op:02x}')
            max_reg_idx = max(max_reg_idx, r1, r2)
        else:
            print(f'0x{vmPc:04x}: unknown opcode 0x{op:02x}')
            vmPc += 1
    print(f'max register index:{max_reg_idx}')

if (__name__ == '__main__'):
    for i in range(1, len(sys.argv)):
        path = sys.argv[i]
        exe = ELF(path)
        context.binary = exe
        sys.stdout = open(f'{path}.log', 'w')
        parse_ops(exe)