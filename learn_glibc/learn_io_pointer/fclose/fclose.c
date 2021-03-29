#include <stdio.h>
#include <stdlib.h>


int main(int argc, char** argv)
{
	char* data = malloc(0x100);
	FILE* fp = fopen("test", "w");
	fwrite(data, 1, 0x60, fp);
	fclose(fp);
	return 0;
}
