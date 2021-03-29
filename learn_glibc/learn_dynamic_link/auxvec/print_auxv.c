#include <stdio.h>
#include <elf.h>

#ifdef X86
	typedef Elf32_auxv_t AUX_T;
#else
	typedef Elf64_auxv_t AUX_T;
#endif

typedef struct AuxDesc {
	char* pName;
	char* pDetial;
} AuxDesc_t;

AuxDesc_t aux_map[52] = {
	{"AT_NULL"			, "End of vector"}, 
	{"AT_IGNORE"		, "Entry should be ignored"},
	{"AT_EXECFD"		, "File descriptor of program"},
	{"AT_PHDR"			, "Program headers for program"},
	{"AT_PHENT"			, "Size of program header entry"},
	{"AT_PHNUM"			, "Number of program headers"},
	{"AT_PAGESZ"		, "System page size"},
	{"AT_BASE"			, "Base address of interpreter"},
	{"AT_FLAGS"			, "Flags"},
	{"AT_ENTRY"			, "Entry point of program"},
	{"AT_NOTELF"		, "Program is not ELF"},
	{"AT_UID"			, "Real uid"},
	{"AT_EUID"			, "Effective uid"},
	{"AT_GID"			, "Real gid"},
	{"AT_EGID"			, "Effective gid"},
	{"AT_CLKTCK"		, "Frequency of times()"},
	{"AT_PLATFORM"		, "String identifying platform."},
	{"AT_HWCAP"			, "Machine-dependent hints about processor capabilities."},
	{"AT_FPUCW"			, "Used FPU control word. "},
	{"AT_DCACHEBSIZE"	, "Data cache block size. "},
	{"AT_ICACHEBSIZE"	, "Instruction cache block size. "},
	{"AT_UCACHEBSIZE"	, "Unified cache block size. "},
	{"AT_IGNOREPPC"		, "Entry should be ignored. "},
	{"AT_SECURE	23"		, "Boolean, was exec setuid-like? "},
	{"AT_BASE_PLATFORM"	, "String identifying real platforms."},
	{"AT_RANDOM"		, "Address of 16 random bytes. "},
	{"AT_HWCAP2"		, "More machine-dependent hints about processor capabilities."},
	
	[32]={"AT_EXECFN"		, "Filename of executable. "},
	{"AT_SYSINFO"	,""}, 
	{"AT_SYSINFO_EHDR"	, ""},
	{"AT_L1I_CACHESHAPE",""},
	{"AT_L1D_CACHESHAPE", ""},
	{"AT_L2_CACHESHAPE"	, ""},
	{"AT_L3_CACHESHAPE"	, ""},

	[40]={"AT_L1I_CACHESIZE"	, ""},
	{"AT_L1I_CACHEGEOMETRY"	, ""},
	{"AT_L1D_CACHESIZE"		, ""},
	{"AT_L1D_CACHEGEOMETRY"	, ""},
	{"AT_L2_CACHESIZE"		, ""},
	{"AT_L2_CACHEGEOMETRY"	, ""},
	{"AT_L3_CACHESIZE"		, ""},
	{"AT_L3_CACHEGEOMETRY"	, ""},

	[51]={"AT_MINSIGSTKSZ", "Stack needed for signal delivery (AArch64)."}
};

int main(int argc, char** argv)
{
	char** p = argv;
	int i = 0;
	AUX_T* auxv = NULL;

	printf("Argument(s) count: %d\n", argc);
	for (i = 0; i < argc; ++i)
		printf("argv[%d]: %s\n", i, p[i]);
	
	p = argv + i;
	++p; // skip NULL

	printf("Environment:\n");
	while (*p) {
		printf("%s\n", *p);
		++p;
	}
		
	++p; // skip NULL
	printf("Auxiliary Vectors:\n");
	for (auxv = (AUX_T*)p; auxv && auxv->a_type; ++auxv) {
		printf("Type(%d): %s\nDesc: %s\nValue: %#x\n\n", auxv->a_type, aux_map[auxv->a_type].pName
			, aux_map[auxv->a_type].pDetial
			, auxv->a_un.a_val);
	}
		
	return 0;
}
