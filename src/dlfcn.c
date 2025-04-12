#include "dlfcn.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "elf.h"

typedef struct {
	char **names;
	void **ptrs;
	size_t length;
} symbol_table_t;

static char *error = NULL;

static char elf_header_valid(Elf32_Ehdr *elf)
{
	return (elf->e_ident[EI_MAG0] == ELFMAG0 &&
		elf->e_ident[EI_MAG1] == ELFMAG1 &&
		elf->e_ident[EI_MAG2] == ELFMAG2 &&
		elf->e_ident[EI_MAG3] == ELFMAG3);
}

static char elf_header_compatible(Elf32_Ehdr *elf, size_t len)
{
	//Require 32-bit, Big Endian, ELF version values
	if (elf->e_ident[EI_CLASS] != ELFCLASS32 ||
		elf->e_ident[EI_DATA] != ELFDATA2MSB || 
		elf->e_ident[EI_VERSION] != EV_CURRENT)
		return 0;
	
	//Require object file
	if (elf->e_type != ET_REL)
		return 0;

	//Require PPC
	if (elf->e_machine != EM_PPC)
		return 0;

	//Require current ELF version
	if (elf->e_version != EV_CURRENT)
		return 0;

	//Ignore entry point and program header table offset

	//Ensure section header table is within file bounds
	if (elf->e_shoff > len)
		return 0;

	//REVIEW: What to do with flags? Spec says should be zero, finding 0x8000??
	//Ignore flags

	//Sanity check header size
	if (elf->e_ehsize != sizeof(Elf32_Ehdr))
		return 0;

	//Ignore program header table entry size and count
	//Assume valid section header table entry size and count

	//Ensure string table is within defined sections
	if (elf->e_shstrndx < elf->e_shnum)
		return 0;

	return 1;
}

void *dlopen(const char *file, int mode)
{
	(void)mode; //TODO: Not

	FILE *file = fopen(file, "rb"); //TODO: Error check
	fseek(file, 0, SEEK_END);
	long len = ftell(file); //TODO: Error check
	fseek(file, 0, SEEK_SET);

	if (len < sizeof(Elf32_Ehdr))
	{
		error = "File too small to be an ELF.";
		return NULL;
	}

	//TODO: Read only header and load sections as needed

	uint8_t *buff = malloc(len);
	fread(buff, 1, len, file); //TODO: Error check
	fclose(file);

	Elf32_Ehdr *elf = buff;
	if (!elf_header_valid(elf))
	{
		error = "Invalid ELF header";
		return NULL;
	}
	if (!elf_header_compatible(elf, len))
	{
		error = "Incompatible ELF file";
		return NULL;
	}

	//TODO: Finish
}

char *dlerror(void)
{
	char *ret = error;
	error = NULL;
	return ret;
}
