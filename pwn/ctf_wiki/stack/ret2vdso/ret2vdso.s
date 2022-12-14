;//    gcc -c ret2vdso.s -o ret2vdso.o -m32
;//    ld -e _start -z noexecstack -melf_i386 ret2vdso.o -o ret2vdso
	.intel_syntax noprefix
	.text
	.comm	buf, 4096, 32
	.globl	_start
	.type	_start, @function
_start:
	xor ebp, ebp
	and esp, 0xfffffff0
	call main
	
	mov ebx, eax
	mov eax, 1
	int 0x80

read:
    push ebp
    mov ebp, esp

    mov ebx, 8[ebp]
    mov ecx, 12[ebp]
    mov edx, 16[ebp]
    mov eax, 3
    int 0x80

    mov esp, ebp
    pop ebp
    ret	

write:
    push ebp
    mov ebp, esp

    mov ebx, 8[ebp]
    mov ecx, 12[ebp]
    mov edx, 16[ebp]
    mov eax, 4
    int 0x80

    mov esp, ebp
    pop ebp
    ret	

memcpy:
	push	ebp
	mov	ebp, esp
	sub	esp, 16
	mov	DWORD PTR -4[ebp], 0
	jmp	.L2
.L3:
	mov	edx, DWORD PTR -4[ebp]
	mov	eax, DWORD PTR 12[ebp]
	add	eax, edx
	mov	ecx, DWORD PTR -4[ebp]
	mov	edx, DWORD PTR 8[ebp]
	add	edx, ecx
	movzx	eax, BYTE PTR [eax]
	mov	BYTE PTR [edx], al
	add	DWORD PTR -4[ebp], 1
.L2:
	mov	eax, DWORD PTR -4[ebp]
	cmp	DWORD PTR 16[ebp], eax
	ja	.L3
	leave
	ret

main:
	push ebp
	mov	ebp, esp
	sub	esp, 128
	lea	eax, buf
	push 4096
	push eax
	push 0
	mov	eax, 0
	call	read
    add esp, 12

	mov esi, eax

	push esi
	lea eax, buf
    push eax 
	lea eax, -128[ebp]
	push eax
	call memcpy
	add esp, 12

    lea eax, -128[ebp]
	push esi
    push eax
    push 1
	mov	eax, 0
	call	write
    add esp, 12

	mov	eax, 0
    mov esp, ebp
    pop ebp
	ret
