#define _GNU_SOURCE
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <stdlib.h>
#include <sys/fcntl.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>


// __attribute__((constructor))
static void antidbg() {
    puts("Anti-dbg is loaded.");
    if (ptrace(PTRACE_TRACEME, 0, 0) == -1) {
        printf("Debug is not allowed!\n");
        // exit(-1);
    }
}

void show_current_resuid() 
{
    int ruid, euid, suid;
    int rgid, egid, sgid;
    getresuid(&ruid, &euid, &suid);
    getresgid(&rgid, &egid, &sgid);
    printf("ruid:%d\neuid:%d\nsuid:%d\n", ruid, euid, suid);
    printf("rgid:%d\negid:%d\nsgid:%d\n", rgid, egid, sgid);
    fflush(stdout);
}

void show_flag()
{
    int fd = open("./flag", O_RDONLY);
    if (fd < 0) {
        perror("open flag failed.");
        exit(-1);
    } else {
        puts("Your flag:");
    }
    char buf[0x100] = {0};
    int bytes_read = 0;
    while ((bytes_read = read(fd, buf, sizeof(buf))) != 0) {
        if (bytes_read < 0) {
            perror("read fialed");
            exit(-1);
        }
        write(1, buf ,bytes_read);
    }
}

int main(int argc, char** argv)
{
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork failed");
        exit(-1);
    } else if (pid) {
        ptrace(PTRACE_ATTACH, pid);
        ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACEEXEC);
        ptrace(PTRACE_SYSCALL, pid);
        while (1) {
            int status;
            struct user_regs_struct regs = {0};

            waitpid(pid, &status, NULL);
            if (WIFEXITED(status)) {
                puts("The child exit normally.");
                break;
            }
            int org_rax = ptrace(PTRACE_PEEKUSER, pid, 8*ORIG_RAX, 0);
            if (org_rax == SYS_write) {
                ptrace(PTRACE_GETREGS, pid,  &regs, 0);
                printf(
                    "SYS_write is calling or returning: rax=%d rdi=%d rsi=%d rdx=%d\n"
                    , regs.rax
                    , regs.rdi
                    , regs.rsi
                    , regs.rdx
                );
            } else if (org_rax == -1) {
                perror("PTRACE_PEEKUSER failed.");
            }
        }
        ptrace(PTRACE_DETACH, pid);
    } else {
        // antidbg();
        puts("Before seteuid explicitly:");
        show_current_resuid();

        // sleep(3);
        puts("After seteuid to 1000 explicitly:");
        seteuid(1000);
        setuid(1000);
        // syscall(SYS_setresuid, 1000, 1000, 1000);
        // syscall(SYS_setresgid, 1000, 1000, 1000);
        show_current_resuid();

        show_flag();
        
        execve("/bin/sh", 0, 0);
    }
    return 0;
}