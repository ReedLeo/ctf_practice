
def vm_mov_reg_imm(curPc):
    ridx = get_wide_dword(curPc + 4) - 1
    imm = get_wide_dword(curPc + 8)
    return (f'8, mov reg[{ridx}], 0x{imm:x}; vmPc+=3; ')


def vm_pop(curPc):
    ridx = get_wide_dword(curPc + 4) - 1
    return (f'9, pop reg[{ridx}], ++vmSp, vmPc += 2')


def vm_push(curPc):
    ridx = get_wide_dword(curPc + 4) - 1
    return (f'10, push reg[{ridx}], --vmSp, vmPc+=2')


def vm_getchar(curPc):
    return ('11, r0 = getchar(), ++vmPc')


def vm_putchar(curPc):
    return ('12, putchar(r0), ++vmPc')


def vm_cmp(curPc):
    ridx1 = get_wide_dword(curPc + 4) - 1
    ridx2 = get_wide_dword(curPc + 8) - 1
    return (f'13, cmp reg[{ridx1}], reg[{ridx2}], vmPc+=3, and set flags')


def vm_jmp(curPc):
    imm = get_wide_dword(curPc + 4)
    return (f'14, jmp, vmPc = &pOpcodes[0x{imm:x}]')


def vm_jnz(curPc):
    imm = get_wide_dword(curPc + 4)
    return (f'15, jnz, if (flags.eq == 0) vmPc = &pOpcodes[0x{imm:x}]')


def vm_jz(curPc):
    imm = get_wide_dword(curPc + 4)
    return (f'16, jz, if (flag.eq == 1) vmPc = &pOpcode[0x{imm:x}]')


def vm_inc_reg(curPc):
    ridx = get_wide_dword(curPc+4)
    return (f'17, ++reg[{ridx}], vmPc+=2')


def vm_dec_reg(curPc):
    ridx = get_wide_dword(curPc+4)
    return (f'18, --reg[{ridx}], vmPc+=2')


def vm_add_reg_imm(curPc):
    ridx = get_wide_dword(curPc+4) - 1
    imm = get_wide_dword(curPc+8)
    return (f'19, reg[{ridx}] += 0x{imm:x}, vmPc += 3')


def vm_sub_reg(curPc):
    ridx1 = get_wide_dword(curPc+4) - 1
    ridx2 = get_wide_dword(curPc+8) - 1
    return (f'20, reg[{ridx1}] -= reg[{ridx2}], vmPc += 3')


def vm_xor_reg(curPc):
    ridx1 = get_wide_dword(curPc+4) - 1
    imm = get_wide_dword(curPc+8)
    return (f'21, reg[{ridx1}] ^= 0x{imm:x}, vmPc += 3')


def vm_and_reg(curPc):
    ridx1 = get_wide_dword(curPc+4) - 1
    ridx2 = get_wide_dword(curPc+8) - 1
    return (f'22, reg[{ridx1}] &= reg[{ridx2}], vmPc += 3')


def vm_or_reg(curPc):
    ridx1 = get_wide_dword(curPc+4) - 1
    ridx2 = get_wide_dword(curPc+8) - 1
    return (f'23, reg[{ridx1}] |= reg[{ridx2}], vmPc += 3')


def vm_mov_reg(curPc):
    ridx1 = get_wide_dword(curPc+4) - 1
    ridx2 = get_wide_dword(curPc+8) - 1
    return (f'25, reg[{ridx1}] = reg[{ridx2}], vmPc += 3')


def vm_get_reg_ptr(curPc):
    ridx1 = get_wide_dword(curPc+4) - 1
    ridx2 = get_wide_dword(curPc+8) - 1
    return (f'26, reg[{ridx1}] = &reg[{ridx2}], vmPc += 3')


def vm_deref_reg(curPc):
    ridx1 = get_wide_dword(curPc+4) - 1
    ridx2 = get_wide_dword(curPc+8) - 1
    return (f'27, reg[{ridx1}] = *reg[{ridx2}], vmPc += 3')


def vm_mov_to_mem(curPc):
    ridx1 = get_wide_dword(curPc+4) - 1
    ridx2 = get_wide_dword(curPc+8) - 1
    return (f'28, *reg[{ridx1}] = reg[{ridx2}], vmPc += 3')


def vm_mul_imm(curPc):
    ridx = get_wide_dword(curPc+4) - 1
    imm = get_wide_dword(curPc+8)
    return (f'29, reg[{ridx}] *= 0x{imm:x}, vmPc += 3')


def vm_check(curPc):
    return ('100, check to encrypted text')


op_mp = {
    8:    (vm_mov_reg_imm, 3),
    9:    (vm_pop, 2),
    0xA:  (vm_push,  2),
    0xB:  (vm_getchar,  1),
    0xC:  (vm_putchar,  1),
    0xD:  (vm_cmp,  3),
    0xE:  (vm_jmp,  2),
    0xF:  (vm_jnz,  2),
    0x10: (vm_jz,  2),
    0x11: (vm_inc_reg,  2),
    0x12: (vm_dec_reg, 2),
    0x13: (vm_add_reg_imm, 3),
    0x14: (vm_sub_reg, 3),
    0x15: (vm_xor_reg, 3),
    0x16: (vm_and_reg, 3),
    0x17: (vm_or_reg, 3),
    0x19: (vm_mov_reg, 3),
    0x1A: (vm_get_reg_ptr, 3),
    0x1B: (vm_deref_reg, 3),
    0x1C: (vm_mov_to_mem, 3),
    0x1D: (vm_mul_imm, 3),
    0x64: (vm_check, 1),
}

op_start = 0x6021C0
op_end = op_start + 400


def parse_ops():
   ea = op_start
   while ea < op_end:
        op = get_wide_dword(ea)
        relative_pc = (ea - op_start) // 4
        op_msg = "-, nop, vmPc+=1"
        parser = op_mp.get(op)
        if parser:
            op_msg = parser[0](ea)
            ea += parser[1]*4
        else:
            ea += 4
        print(f'0x{relative_pc:x}: {op_msg}')
