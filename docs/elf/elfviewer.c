#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define err_exit(msg) { fprintf(stderr, "%s\n", msg); exit(EXIT_FAILURE); }
#define print_member(ptr, mem, fmt) { printf(#mem ": " fmt "\n", ptr->mem); }

int main(int argc, char** argv)
{
	int fd;
	off_t filesz = -1;
	Elf64_Ehdr* pEhdr = NULL;


	if (argc < 2) 
		err_exit("Usage: elfviewer [filename]");			
	
	if ( (fd = open(argv[1], O_RDONLY) ) < 0)
		err_exit(strerror(errno));
	
	if ( (filesz = lseek(fd, 0, SEEK_END)) < 0)
		err_exit(strerror(errno));
	
	pEhdr = mmap(NULL, filesz, PROT_READ, MAP_PRIVATE, fd, 0);
	if (pEhdr == (void*)-1)
		err_exit(strerror(errno));
	close(fd);

	printf("e_ident[16]:");
	for (int i = 0; i < EI_NIDENT; ++i)
		printf(" %02x", pEhdr->e_ident[i]);
	puts("");
	print_member(pEhdr, e_type,		"%#04x");
	print_member(pEhdr, e_machine,	"%#04x");
	print_member(pEhdr, e_version,	"%#08x");
	print_member(pEhdr, e_entry,		"%#llx");
	print_member(pEhdr, e_phoff,		"%#llx");
	print_member(pEhdr, e_shoff,		"%#llx");
	print_member(pEhdr, e_flags,		"%#08x");
	print_member(pEhdr, e_ehsize,		"%#04x");
	print_member(pEhdr, e_phentsize,	"%#04x");
	print_member(pEhdr, e_phnum,		"%#04x");
	print_member(pEhdr, e_shentsize, 	"%#04x");
	print_member(pEhdr, e_shnum, 		"%#04x");
	print_member(pEhdr, e_shstrndx, 	"%#04x");
	
	return 0;
}
