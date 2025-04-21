#ifndef DATA_H_
#define DATA_H_

#include <stdio.h>

#include "elf.h"

typedef struct {
	FILE *file;
	Elf32_Ehdr header;
	Elf32_Shdr *sects;
	char *sh_strings;
} elf_file_t;

typedef struct {
	char *name;
	Elf32_Off offset;
	Elf32_Sword addend;
	Elf32_Half section;
	unsigned char rel_type;
} rel_symbol_t;

typedef struct {
	char *name;
	Elf32_Addr value;
	unsigned char bind;
	unsigned char type;
	int section;
} def_symbol_t;

typedef struct {
	elf_file_t elf;
	rel_symbol_t *relocations;
	int rel_count;
	def_symbol_t *symbols;
	int sym_count;
	//void *sect_text;
	//void *sect_data;
	//void *sect_rodata;
} elf_rel_t;

typedef struct {
	elf_file_t elf;
	def_symbol_t *symbols;
	int sym_count;
} elf_exec_t;

elf_rel_t *elf_rel_create(const char *path, char **error);
void elf_rel_destroy(elf_rel_t *obj);

elf_exec_t *elf_exec_create(const char *path, char **error);
void elf_exec_destroy(elf_exec_t *exec);

#endif
