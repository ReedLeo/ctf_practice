#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <sys/user.h>

struct user_regs_struct regs;

int main(int argc, char** argv, char** env)
{
    char opt[16] = {0};
    int status;
    int org_rax;
    int iscalling = 0;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s [ELF_to_exec]\n", argv[0]);
        exit(-1);
    }
    pid_t pid;
    pid = fork();
    if (pid) {
        // ptrace(PTRACE_ATTACH, pid, 0, 0);
        //ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACEEXEC);
        for (int cnt = 0;;) {
            waitpid(pid, &status, 0);
            if (WIFEXITED(status)) {
                break;
            }
            org_rax = ptrace(PTRACE_PEEKUSER, pid, sizeof(size_t)*ORIG_RAX, 0);
            if (org_rax == SYS_write) {
                ptrace(PTRACE_GETREGS, pid, 0, &regs);
                if (!iscalling) {
                    printf("SYS_write call with %p, %p, %p\n", regs.rbx, regs.rcx, regs.rdx);
                } else {
                    printf("SYS_write call return %#x\n", regs.rax);
                }
                iscalling = !iscalling;
                if (++cnt >= 10) {
                    break;
                }
            } else if (org_rax == -1) {
                perror("PTRACE_PEEKUSER failed.");
            }
            ptrace(PTRACE_SYSCALL, pid, 0, 0);
        }
        // ptrace(PTRACE_DETACH, pid);
        ptrace(PTRACE_CONT, pid);
        printf("The child %s(%d) has exited.\n", argv[1], pid);
    } else if (pid < 0) {
        perror("fork failed.");
        exit(-1);
    } else {
        printf("Now you'll run %s\n", argv[1]);
        if (argc >= 3) {
            printf("And it running as the tracee.\n");
            // ptrace(PTRACE_TRACEME, 0, 0);
        }
        execve(argv[1], NULL, env);
    }
    return 0;
}