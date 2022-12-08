#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char** argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s [captcha]\n", argv[0]);
        exit(-1);
    }
    int captcha = atoi(argv[1]);
    int v[8]={0};
    srand(time(0));
    for (int i = 0; i < 8; ++i){
        v[i] = rand();
    }
    int canary = captcha - (v[4] - v[6] + v[7] + v[2] - v[3] + v[1] + v[5]);
    printf("Your canary: %d\n", canary);    
    return 0;
}