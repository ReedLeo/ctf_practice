#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <stdlib.h>

void show_ids()
{    
    uid_t uid, euid, suid, gid, egid, sgid;
    // uid = getuid();
    // euid = geteuid();
    getresuid(&uid, &euid, &suid);
    // gid = getgid();
    // egid = getegid();
    getresgid(&gid, &egid, &sgid);
    printf("uid:%d, euid:%d, suid:%d, gid:%d, egid:%d, sgid:%d\n\n"
        , uid
        , euid
        , suid
        , gid
        , egid
        , sgid
    );
}

void set_ids() {
    setuid(1000);   // set effective user id
    seteuid(1000);
    setgid(1000);
    setegid(1000);
}

void set_reids() {
    setreuid(1000, 1000);
    setregid(1000, 1000);
}

void set_resids() {
    setresuid(1000, 1000, 1000);
    setresgid(1000, 1000, 1000);
}

#define TARGET_NAME "getflag"

typedef void (*id_setter_fn_t)(void);

struct setter_st {
    id_setter_fn_t pfn_setter;
    char* const p_name;
};

static 
struct setter_st gs_setters[] = {
    { set_ids, "set(u|g)id/sete(u|g)id" },
    { set_reids, "set\x1b[32mre\x1b[0m(u|g)id" }, 
    { set_resids, "set\x1b[31mres\x1b[0m(u|g)id" }
};

int prompt() {
    puts("Now plese select which setter to use:");
    for (int i = 0; i < 3; ++i) {
        printf("%d. %s\n", i+1, gs_setters[i].p_name);
    }
    int opt = 0;
    scanf("%d", &opt);
    return opt - 1;
}

int main(int argc, char** argv, char** envp)
{
    pid_t self_pid = getpid();

    puts("Before PTRACEME:");
    show_ids();
    if (-1 == ptrace(PTRACE_TRACEME)) {
        perror("TRACEME failed.");
    }
    puts("After PTRACEME:");
    show_ids();

    // prompt
    int opt = prompt();
    puts("After set id:");
    printf("Now we use %s:\n", gs_setters[opt].p_name);
    gs_setters[opt].pfn_setter();
    show_ids();
    kill(self_pid, SIGTRAP);
    char* _argv[] = {TARGET_NAME, 0};
    execve(TARGET_NAME, _argv, envp);
    return 0;
}