# mprotect(stack_addr, 0x2000, 7)
# eax 
# define PROT_EXEC 0x4 
# define PROT_WRITE 0x2  
# define PROT_READ 0x1 

# 0x00000b5a : pop edx ; pop ecx ; ret