import ctypes

filtered_addr = [
    0x4027b0,
    0x4023df,
    0x4022fd,
    0x4024EE,
    0x402412,
    0x402621,
    0x4020a8,
    0x402210,
    0x4020cc,
    0x40219D,
    0x4026c5,
    0x4022a5,
    0x402670,
    0x4023B0,
    0x402453, # read_line_vm_handler
]

addr_to_handler_name = {
    0x4027b0: 'push_imm()',
    0x402621: 'add()',
    0x4024ee: 'pop_to_idx()',
    0x4023df: 'push_from_idx()',
    0x4022fd: 'dup_cur_top()',
    0x40219d: 'swap()',
    0x4020a8: 'jnz()',
    0x402412: 'less()',
    0x402210: 'equal()',
    0x4020cc: 'jmp()',
    0x4026c5: 'sar()',
    0x4022a5: 'and()',
    0x402670: 'shl()',
    0x402453: 'read_line()',
    0x4023b0: 'jz()',
    0x4020d5: 'write_line()',
    0x402085: 'exit_vm()',
}

addr_to_opcode = {
    0x4027b0: 0x2F,
    0x402621: 0xFE,
    0x4024ee: 0x86,
    0x4023df: 0xE2,
    0x4022fd: 0xD2,
    0x40219d: 0xF8,
    0x4020a8: 0xED,
    0x402412: 0xAB,
    0x402210: 0xF6,
    0x4020cc: 0x00, # to fix
    0x4026c5: 0x3E,
    0x4022a5: 0xD4,
    0x402670: 0x4F,
    0x402453: 0x9A,
    0x4023b0: 0x26,
    0x4020d5: 0xB1,
    0x402085: 0x00, # to fix
}

rdx = get_reg_value('rdx')
rbx = get_reg_value('rbx')
vmSp = ctypes.c_int32(read_dbg_dword(rbx+0x20)).value
vmPc = read_dbg_dword(rbx+0x1c) - 1
vmStackBase = read_dbg_qword(rbx)
pOpcodes = read_dbg_qword(rbx+0x10)

def parse_push_imm():
    # fn_name = inspect.stack()[0][3]
    imm = read_dbg_dword(pOpcodes+4*(vmPc+1))
    print(f'\tpush(0x{imm:x})')

def parse_add():
    # fn_name = inspect.stack()[0][3]
    a = read_dbg_dword(vmStackBase+4*vmSp)
    b = read_dbg_dword(vmStackBase+4*vmSp-4)
    c = a+b
    c &= 0xffffffff
    print(f'\tpop() -> a=0x{a:x}')
    print(f'\tpop() -> b=0x{b:x}')
    print(f'\tpush(0x{c:x})')

def parse_pop_to_idx():
    idx = read_dbg_dword(vmStackBase+4*vmSp)
    val = read_dbg_dword(vmStackBase+4*vmSp-4)
    print(f'\tpop() -> idx=0x{idx:x}')
    print(f'\tpop() -> val=0x{val:x}')
    orgVal = read_dbg_dword(vmStackBase+4*idx)
    print(f'\tvmStack[{idx:x}](@{vmStackBase+4*idx:x}) = 0x{val:x}, where orignial value=0x{orgVal:x}')

def parse_push_from_idx():
    idx = read_dbg_dword(vmStackBase+4*vmSp)
    val = read_dbg_dword(vmStackBase+4*idx)
    print(f'\tpop() -> idx=0x{idx:x}')
    print(f'\tpush(0x{val:x}), vmStack[0x{idx:x}]==0x{val:x}')

def parse_dup_cur_top():
    a = read_dbg_dword(vmStackBase+4*vmSp)
    print(f'\tpop() -> a=0x{a:x}')
    print(f'\tpush(0x{a:x})')
    print(f'\tpush(0x{a:x})')

def parse_swap():
    a = read_dbg_dword(vmStackBase+4*vmSp)
    b = read_dbg_dword(vmStackBase+4*vmSp-4)
    print(f'\tpop() -> a=0x{a:x}')
    print(f'\tpop() -> b=0x{b:x}')
    print(f'\tpush(0x{a:x})')
    print(f'\tpush(0x{b:x})')

def parse_jnz():
    res = read_dbg_dword(vmStackBase+4*vmSp)
    target_pc = read_dbg_dword(pOpcodes+4*(vmPc+1))
    print(f'\tpop() -> res=0x{res:x}')
    if (res):
        print(f'\tjmp to pOpcode[0x{vmPc+1:x}] = 0x{target_pc:x}')
    else:
        print('\tcontinue')

def parse_less():
    a = read_dbg_dword(vmStackBase+4*vmSp)
    b = read_dbg_dword(vmStackBase+4*vmSp-4)
    isLess = 1 if b < a else 0
    print(f'\tpop() -> a=0x{a:x}')
    print(f'\tpop() -> b=0x{b:x}')
    print(f'\tpush(0x{isLess:x}), b(0x{b:x}) < a(0x{a:x}) == {b<a}')

def parse_equal():
    a = read_dbg_dword(vmStackBase+4*vmSp)
    b = read_dbg_dword(vmStackBase+4*vmSp-4)
    isEqual = 1 if b == a else 0
    print(f'\tpop() -> a=0x{a:x}')
    print(f'\tpop() -> b=0x{b:x}')
    print(f'\tpush(0x{isEqual:x})')

def parse_jmp():
    target_pc = read_dbg_dword(pOpcodes+4*(vmPc+1))
    print(f'\tjmp to pOpcode[0x{vmPc+1:x}] = 0x{target_pc:x}')

def parse_sar():
    bit_to_shift = read_dbg_dword(vmStackBase+4*vmSp) & 0xff
    val = read_dbg_dword(vmStackBase+4*vmSp-4)
    tmp = (val >> bit_to_shift) & 0xffffffff
    print(f'\tpop() -> bit_to_shift=0x{bit_to_shift:x}')
    print(f'\tpop() -> val=0x{val:x}')
    print(f'\tpush(0x{tmp:x})')


def parse_and():
    a = read_dbg_dword(vmStackBase+4*vmSp)
    b = read_dbg_dword(vmStackBase+4*vmSp-4)
    tmp = a & b
    print(f'\tpop() -> a=0x{a:x}')
    print(f'\tpop() -> b=0x{b:x}')
    print(f'\tpush(0x{tmp:x})')

def parse_shl():
    bit_to_shift = read_dbg_dword(vmStackBase+4*vmSp) & 0xff
    val = read_dbg_dword(vmStackBase+4*vmSp-4)
    tmp = val << bit_to_shift
    print(f'\tpop() -> bit_to_shift=0x{bit_to_shift:x}')
    print(f'\tpop() -> val=0x{val:x}')
    print(f'\tpush(0x{tmp:x})')

def parse_read_line():
    start_idx = read_dbg_dword(vmStackBase+4*vmSp)
    print(f'\tread(0, &vmStack[0x{start_idx:x}](==0x{vmStackBase+4*start_idx:x}), 200)')

def parse_jz():
    res = read_dbg_dword(vmStackBase+4*vmSp)
    target_pc = read_dbg_dword(pOpcodes+4*vmPc+4)
    print(f'\tpop() -> res=0x{res:x}')
    if (res):
        print(f'\tcontinue')
    else:
        print(f'\tjmp to pOpcode[0x{vmPc+1}]=0x{target_pc}')

def parse_write_line():
    start_idx = read_dbg_dword(vmStackBase+4*vmSp)
    start_addr = vmStackBase+4*start_idx
    print(f'\twrite(0, &vmStack[0x{start_idx:x}](==0x{start_addr:x}), 200)')

def parse_exit_vm():
    print('\tExit VM!!')

addr_to_parse = {
    0x4027b0: parse_push_imm,
    0x402621: parse_add,
    0x4024ee: parse_pop_to_idx,
    0x4023df: parse_push_from_idx,
    0x4022fd: parse_dup_cur_top,
    0x40219d: parse_swap,
    0x4020a8: parse_jnz,
    0x402412: parse_less,
    0x402210: parse_equal,
    0x4020cc: parse_jmp,
    0x4026c5: parse_sar,
    0x4022a5: parse_and,
    0x402670: parse_shl,
    0x402453: parse_read_line,
    0x4023b0: parse_jz,
    0x4020d5: parse_write_line,
    0x402085: parse_exit_vm,
}

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
    op = read_dbg_dword(pOpcodes+4*(vmPc))
    print(f'rdx=0x{rdx:x}: {addr_to_handler_name[rdx]}, opcode 0x{op:x}')
    addr_to_parse[rdx]()
    print(f'vmPc=0x{vmPc:x}, Opcodes@0x{pOpcodes:x}[0x{vmPc:x}:0x{vmPc+6:x}]=')
    print('\t', '|'.join(map(hex, opcodes)))
    print(f'vmSp=0x{vmSp:x}, Stack@0x{vmStackBase:x}[0x{vmSp:x}:0x{vmSp-6:x}]=')
    print('\t', '|'.join(map(hex, stkvals)))
    print()

print_dbg_info()
if( rdx == 0x402453 ):
    return True
else:
    return False