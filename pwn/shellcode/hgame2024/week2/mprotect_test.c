#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#include <assert.h>

int main()
{
    void* p1 = mmap((void*)0xdead0000, 0x1000, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    if (p1 == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }
    void* p2 = p1 + 0x2000;
    assert(p2 == mmap(p2, 0x1000, PROT_NONE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0));

    int res = mprotect(p1, 0x1000, PROT_NONE);
    if (res) {
        perror("mprotect");
        exit(-1);
    }

    res = mprotect(p1, 0x1234, PROT_READ|PROT_WRITE);
    if (res) {
        printf("erno=%d: %s\n", errno, strerror(errno));
    }

    res = mprotect(p1, 0x1000, 0x2333);
    if (res) {
        printf("erno=%d: %s\n", errno, strerror(errno));
    }

    res = mprotect(p1+0xbeef, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC|PROT_GROWSDOWN);
    if (res) {
        printf("erno=%d: %s\n", errno, strerror(errno));
    }

    res = mprotect(p1, 0x2333, PROT_READ|PROT_WRITE|PROT_EXEC);
    if (res) {
        printf("erno=%d: %s\n", errno, strerror(errno));
    }

    return 0;
}