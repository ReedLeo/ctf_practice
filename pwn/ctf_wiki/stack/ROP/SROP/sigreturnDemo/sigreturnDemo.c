#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

void handler(int sig)
{
    printf("Outch!!\n");
}

void rt_handler(int sig, siginfo_t* si, void* ucontext) {
    printf("Caught signal: %d\n", sig);
}

int main(int argc, char** argv)
{
    char buf[0x101] = {0};
    struct sigaction sa;

    sa.sa_sigaction = rt_handler;
    sa.sa_flags = SA_SIGINFO;
    sigfillset(&sa.sa_mask);
    
    printf("The minimum real-time signal number=%d\n", SIGRTMIN);
    if (sigaction(SIGRTMIN, &sa, NULL) == -1) {
        perror("sigaction failed.");
        exit(-1);
    }

    // setvbuf(stdin, NULL, _IONBF, 0);
    // setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGINT, handler);

    printf("Wait for the signal arrvie.\n");
    // scanf("%256s", buf);
    
    pause();
    // printf("What you've input:\n%s", buf);
    return 0;
}