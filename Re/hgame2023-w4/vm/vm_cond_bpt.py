imgBase = idaapi.get_imagebase()
vaOpcodes = imgBase + 0x5360
vaUsrInput = imgBase + 0x5040
vaVmStack = imgBase + 0x5D40
rsp = get_reg_value('rsp')
pVmContext =  read_dbg_qword(rsp+0x40)
regs = [read_dbg_dword(pVmContext+i*4) for i in range(6)]
vmPc = read_dbg_dword(pVmContext+0x18)
vmSp = read_dbg_dword(pVmContext+0x1c)
vmNotEq = read_dbg_byte(pVmContext+0x20)
curOp = read_dbg_byte(vaOpcodes + vmPc)

def vm_mov():
    reg_type = read_dbg_byte(vaOpcodes + vmPc + 1)
    imm1, imm2 = [read_dbg_byte(vaOpcodes + vmPc + 2 + i) for i in range(2)]
    usr_val = read_dbg_dword(vaUsrInput + 4*regs[2])
    if (reg_type == 1):
        print(f'userInput[0x{regs[2]:x}] = 0x{regs[0]:x}, where original value=0x{usr_val:x}')
    elif (reg_type == 2):
        print(f'regs[0x{imm1:x}] = regs[0x{imm2:x}]')
    elif (reg_type == 3):
        print(f'regs[0x{imm1:x}] = 0x{imm2:x}')
    else:
        print(f'regs[0] = userInput[0x{regs[2]:x}] = 0x{usr_val:x}')

def vm_push():
    reg_type = read_dbg_byte(vaOpcodes + vmPc + 1)
    if (reg_type == 1):
        print(f'push_reg0: push(0x{regs[0]:x})')
    elif (reg_type == 2):
        print(f'push_reg2: push(0x{regs[2]:x})')
    elif (reg_type == 3):
        print(f'push_reg3: push(0x{regs[3]:x})')
    else:
        print(f'push_reg0: push(0x{regs[0]:x})')

def vm_pop():
    reg_type = read_dbg_byte(vaOpcodes + vmPc + 1)
    stk_val = read_dbg_dword(vaVmStack + 4*vmSp)
    if (reg_type == 1):
        print(f'pop_reg1: reg0 = pop <- 0x{stk_val:x}')
    elif (reg_type == 2):
        print(f'pop_reg2: reg2 = pop <- 0x{stk_val:x}')
    elif (reg_type == 3):
        print(f'pop_reg3: reg3 = pop <- 0x{stk_val:x}')
    else:
        print(f'pop_reg0: reg0 = pop() <- 0x{stk_val:x}')
    
def vm_arithmetic():
    op_type = read_dbg_byte(vaOpcodes + vmPc + 1)
    imm1, imm2 = [read_dbg_byte(vaOpcodes + vmPc + 2 + i) for i in range(2)]
    a, b = regs[imm1], regs[imm2]
    if (op_type == 0):
        res = (a + b) & 0xFFFFFFFF
        print(f'regs[0x{imm1:x}](==0x{a:x}) += regs[0x{imm2:x}](==0x{b:x}), res=0x{res:x}')
    elif (op_type == 1):
        res = (a - b) & 0xFFFFFFFF
        print(f'regs[0x{imm1:x}](==0x{a:x}) -= regs[0x{imm2:x}](==0x{b:x}), res=0x{res:x}')
    elif (op_type == 2):
        res = (a * b) & 0xFFFFFFFF
        print(f'regs[0x{imm1:x}](==0x{a:x}) *= regs[0x{imm2:x}](==0x{b:x}), res=0x{res:x}')
    elif (op_type == 3):
        res = (a ^ b) & 0xFFFFFFFF
        print(f'regs[0x{imm1:x}](==0x{a:x}) ^= regs[0x{imm2:x}](==0x{b:x}), res=0x{res:x}')
    elif (op_type == 4):
        res = (a << b) & 0xFF00
        print(f'regs[0x{imm1:x}](==0x{a:x}) = (regs[0x{imm1:x}] << regs[0x{imm2:x}](==0x{b:x})) & 0xFF00, res=0x{res:x}')
    elif (op_type == 5):
        res = (a >> b) & 0xFFFFFFFF
        print(f'regs[0x{imm1:x}](==0x{a:x}) = regs[0x{imm1:x}] >> regs[0x{imm2:x}](==0x{b:x}), res=0x{res:x}')
    else:
        print(f'nop, op_type={op_type}')

def vm_cmp():
    a, b = regs[0:2]
    print(f'reg0(0x{a:x}) != reg1(0x{b:x}) -> NotEq={a!=b}')

def vm_jmp():
    newPc = read_dbg_byte(vaOpcodes + vmPc + 1)
    print(f'jump to 0x{newPc:x}')

def vm_jz():
    newPc = read_dbg_byte(vaOpcodes + vmPc + 1)
    if (vmNotEq):
        print(f'NotEq={vmNotEq}, no jump, continue')
    else:
        print(f'NotEq={vmNotEq}, jump to 0x{newPc:x}')

def vm_jnz():
    newPc = read_dbg_byte(vaOpcodes + vmPc + 1)
    if (vmNotEq):
        print(f'NotEq={vmNotEq}, jump to 0x{newPc:x}')
    else:
        print(f'NotEq={vmNotEq}, no jump, continue')

op2handler_map = {
    0: vm_mov,
    1: vm_push,
    2: vm_pop,
    3: vm_arithmetic,
    4: vm_cmp,
    5: vm_jmp,
    6: vm_jz,
    7: vm_jnz
}

op2name_map = {
    0: "vm_mov",
    1: "vm_push",
    2: "vm_pop",
    3: "vm_arithmetic",
    4: "vm_cmp",
    5: "vm_jmp",
    6: "vm_jz",
    7: "vm_jnz"
}

def print_dbg_info():
    rax = get_reg_value('rax')
    print(f'0x{rax:x}: {op2name_map[curOp]}, opcode={curOp}')
    print(f'\tuserInput@0x{vaUsrInput:x}')
    print(f'\tvmStack@0x{vaVmStack:x}')
    print(f'\tvmOpcodes@0x{vaOpcodes:x}')
    print(f'\tvmNotEq=0x{vmNotEq:x}')
    print(f'\tregs=[', ','.join(map(hex, regs)), ']')
    ops = [read_dbg_byte(vaOpcodes + i) for i in range(vmPc, vmPc+10)]
    print(f'\tvmPc(0x{vmPc:x})->', '|'.join(map(hex, ops)))
    stk_vals = [read_dbg_dword(vaVmStack + 4*i) for i in range(max(0, vmSp-9), vmSp+1)]
    print(f'\tvmSp(0x{vmSp:x})->', '|'.join(map(hex, stk_vals[::-1])))
    op2handler_map[curOp]()
    print()

print_dbg_info()

filtered_op = [4, 5, 6, 7]
if (curOp in filtered_op):
    return True
else:
    return False