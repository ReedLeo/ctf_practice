#include <stdio.h>
#include <stdlib.h>

int main()
{
    char* ptr[9] = {0};

    for(int i = 0; i < 9; ++i) {
        ptr[i] = malloc(10);
    }

    for (int i = 0; i < 7; ++i) {
        free(ptr[i]);
    }

    char* p = ptr[7];
    char* q = ptr[8];


    free(p);
    free(q);
    free(p);

    for(int i = 0; i < 7; ++i) {
        malloc(10);
    }

    p = malloc(10);
    printf("p = %p\n", p);

    q = malloc(10);
    printf("q = %p\n", q);
    
    return 0;
}