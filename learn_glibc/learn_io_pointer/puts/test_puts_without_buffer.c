#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv)
{
	char buf[0x30] = "Hello\nworld";
	setbuf(stdout, 0);
	puts(buf);
	return 0;
}
