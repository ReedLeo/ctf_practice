#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

void handler(int sig)
{
    printf("Outch!!\n");
}

int main(int argc, char** argv)
{
    char buf[0x101] = {0};
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGINT, handler);
    printf("Hi, input a string pattern.\n");
    scanf("%256s", buf);
    pause();
    printf("What you've input:\n%s", buf);
    return 0;
}