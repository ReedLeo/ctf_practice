#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv)
{
	char* p = malloc(0x100);
	FILE* fp = fopen("test", "w");
	fwrite(p, 1, 0x80, fp);

	return 0;
}
