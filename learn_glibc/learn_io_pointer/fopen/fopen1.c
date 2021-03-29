#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv)
{
	FILE* fp = fopen("test", "wb");
	malloc(0x20);
	return 0;
}
