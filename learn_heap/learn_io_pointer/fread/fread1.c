#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv)
{
	char buf[128] = {0};
	FILE* fp = fopen("test", "r");
	fread(buf, 128, 1, fp);
	printf("%s\n", buf);

	return 0;
}
