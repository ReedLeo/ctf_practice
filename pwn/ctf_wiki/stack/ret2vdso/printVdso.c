#include <sys/auxv.h>
#include <stdio.h>

int main(int argc, char** argv)
{
    void* vdso = (uintptr_t) getauxval(AT_SYSINFO_EHDR);
    printf("vdso@%p\n", vdso);
    return 0;
}