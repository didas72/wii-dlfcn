#ifndef DATA_H_
#define DATA_H_

#include <stdio.h>

#include "elf.h"

typedef struct {
	char *name;
	Elf32_Off offset;
	Elf32_Sword addend;
	Elf32_Half section;
	unsigned char rel_type;
} rel_symbol_t;

typedef struct {
	FILE *file;
	Elf32_Ehdr elf;
	Elf32_Shdr *sects;
	char *sh_strings;
	rel_symbol_t *relocations;
	int rel_count;
} elf_rel_t;

typedef struct {
	char *name;
	Elf32_Addr addr;
} def_symbol_t;

typedef struct {
	FILE *file;
	Elf32_Ehdr elf;
	def_symbol_t *symbols;
	int sym_count;
} elf_exec_t;

elf_rel_t *elf_rel_create(const char *path, char **error);
void elf_rel_destroy(elf_rel_t *obj);

elf_exec_t *elf_exec_create(char **error);
void elf_exec_destroy(elf_exec_t *exec);

#endif
