/**
* This file shows we cannot get shell in the same terminal,
* if we close STDIN, STDOUT, STDERR.
*/
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#define OPTSTR "anc:"

int main(int argc, char** argv)
{
	int opt;
	if (argc < 2) {
			fprintf(stderr, "Usage: %s [-a close all] [-c fd] [-n close none]\n", argv[0]);
			exit(EXIT_FAILURE);
	}
	while ((opt = getopt(argc, argv, OPTSTR)) != -1) {
		switch (opt) {
		case 'c':
			close(atoi(optarg));
			break;
		case 'a':
			close(0);
			close(1);
			close(2);
			break;
		case 'n':
			/* close none */
			break;
		default:
			fprintf(stderr, "Usage: %s [-a close all] [-c fd] [-n close none]\n", argv[0]);
			exit(EXIT_FAILURE);
		}
	}
	system("/bin/sh");
	return 0;
}
