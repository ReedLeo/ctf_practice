#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

void show_ids() {
    uid_t uid, euid;
    uid = getuid();
    euid = geteuid();
    printf("uid=%d, euid=%d\n\n", uid, euid);
}

void set_ids(uid_t uid) {
    setreuid(uid, uid);
}

int main(int argc, char** argv)
{
    int euid = geteuid();
    int ruid = getuid();

    if (argc > 1) {
        ruid = atoi(argv[1]);
    }
    if (argc > 2) {
        euid = atoi(argv[2]);
    }
    puts("Before setreuid:");
    show_ids();
    puts("After drop privileges:");
    // set_ids(ruid);
    setreuid(-1, euid);
    // setreuid(euid, -1);
    show_ids();
    puts("After re-gain root privileges:");
    set_ids(ruid); // failed regain root privileges, not permitted.
    show_ids();
    puts("Now you'll try to get a root shell.");
    char* _argv[] = {"/bin/sh", 0};
    execve("/bin/sh", argv, 0);
    return 0;
}