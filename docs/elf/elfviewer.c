#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define err_exit(msg) { fprintf(stderr, "%s\n", msg); exit(EXIT_FAILURE); }
#define print_member(ptr, mem, fmt) { printf(#mem ": " fmt "\n", ptr->mem); }
#define at_offset(ptr, off) ((char*)(ptr) + (off))

char* getName(Elf64_Ehdr* pEhdr, Elf64_Shdr* pShdr, Elf64_Word idx)
{
	char* pNameArr = NULL;
	
	assert(pEhdr);
	assert(pShdr);
	assert(SHT_STRTAB == pShdr->sh_type);

	pNameArr = at_offset(pEhdr, pShdr->sh_offset);
	return pNameArr + idx;
}

void listSymName(Elf64_Ehdr* pEhdr, Elf64_Shdr* pSymHdr)
{
	Elf64_Shdr* pStrTbl = NULL;
	Elf64_Shdr* pNameHdr = NULL;
	Elf64_Shdr* pShdrTbl = NULL;
	Elf64_Sym* 	pSymEnt = NULL;
	size_t entnum = 0;

	assert(pEhdr);
	assert(pSymHdr);
	assert(pEhdr->e_shnum > pSymHdr->sh_link);

	pShdrTbl	= (Elf64_Shdr*)at_offset(pEhdr, pEhdr->e_shoff);
	pStrTbl		= pShdrTbl + pEhdr->e_shstrndx;
	pSymEnt		= (Elf64_Sym*)at_offset(pEhdr, pSymHdr->sh_offset);
	pNameHdr	= pShdrTbl + pSymHdr->sh_link;
	entnum		= pSymHdr->sh_size / pSymHdr->sh_entsize;

	printf("   Num:    Value          Size Type    Bind   Vis      Ndx Name\n");
	// skip the entry_0, which is reserved.
	for (size_t i = 1; i < entnum; ++i)
	{
		printf("%-7d: %08x  %04d %s  %s %s  ", i, pSymEnt[i].st_value, pSymEnt[i].st_size
			, ELF64_ST_BIND(pSymEnt[i].st_info)
			, ELF64_ST_TYPE(pSymEnt[i].st_info)
			, 
		);
		printf("\tname: %s\n", getName(pEhdr, pNameHdr, pSymEnt[i].st_name) );
		//printf("\ttype: %s\n", );
	}

}

void parseDynSym(Elf64_Ehdr* pEhdr)
{
	Elf64_Shdr* pShdrTbl = NULL;
	Elf64_Shdr* pDynSecHdr = NULL;
	Elf64_Shdr* pNameSecHdr = NULL;
	uint16_t secnum = 0;

	assert(pEhdr);
	secnum = pEhdr->e_shnum;
	assert(secnum > pEhdr->e_shstrndx);
	pShdrTbl = (Elf64_Shdr*)at_offset(pEhdr, pEhdr->e_shoff);
	pNameSecHdr = pShdrTbl + pEhdr->e_shstrndx;

	for (uint16_t i = 0; i < secnum; ++i)
	{
		if (SHT_DYNSYM == pShdrTbl[i].sh_type)
		{
			printf("==========[Section: %s]===========\n", getName(pEhdr, pNameSecHdr, pShdrTbl[i].sh_name));
			listSymName(pEhdr, &pShdrTbl[i]);
			puts("===================================");
		}
	}
}

int main(int argc, char** argv)
{
	int fd;
	off_t filesz = -1;
	Elf64_Ehdr* pEhdr = NULL;
	Elf64_Phdr* pPhdr = NULL;
	Elf64_Shdr* pShdr = NULL;

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
	print_member(pEhdr, e_type,			"%#04x");
	print_member(pEhdr, e_machine,		"%#04x");
	print_member(pEhdr, e_version,		"%#08x");
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

	parseDynSym(pEhdr);

	munmap(pEhdr, filesz);
	return 0;
}
