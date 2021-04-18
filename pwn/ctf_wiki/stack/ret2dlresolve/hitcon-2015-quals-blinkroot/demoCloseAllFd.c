/**
* This file shows we cannot get shell in the same terminal,
* if we close STDIN, STDOUT, STDERR.
*/
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main(int argc, char** argv)
{
	if (argc > 1) {
		for (int i = 0; i < 3; ++i)
			close(i);
	}

	system("/bin/sh");
	return 0;
}
