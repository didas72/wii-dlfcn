#include "dlfcn.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "data.h"
#include "elf.h"
#include "mmu_dump.h"

static char *error = NULL;
static elf_exec_t *self = NULL;

static char elf_header_valid(elf_obj_t *obj)
{
	if (obj->elf.e_ident[EI_MAG0] != ELFMAG0 ||
		obj->elf.e_ident[EI_MAG1] != ELFMAG1 ||
		obj->elf.e_ident[EI_MAG2] != ELFMAG2 ||
		obj->elf.e_ident[EI_MAG3] != ELFMAG3)
	{
		error = "Invalid ELF magic";
		return 0;
	}

	return 1;
}

static char elf_header_compatible(elf_obj_t *obj)
{
	//Require 32-bit, Big Endian, ELF version values
	if (obj->elf.e_ident[EI_CLASS] != ELFCLASS32 ||
		obj->elf.e_ident[EI_DATA] != ELFDATA2MSB || 
		obj->elf.e_ident[EI_VERSION] != EV_CURRENT)
	{
		error = "Invalid IDENT values";
		return 0;
	}
	
	//Require object file
	if (obj->elf.e_type != ET_REL)
	{
		error = "Unsupported ELF type, must be ET_REL (object file)";
		return 0;
	}

	//Require PPC
	if (obj->elf.e_machine != EM_PPC)
	{
		error = "Invalid target machine";
		return 0;
	}

	//Require current ELF version
	if (obj->elf.e_version != EV_CURRENT)
	{
		error = "Invalid ELF version";
		return 0;
	}

	//Ignore entry point and program header table offset

	//Ensure section header table is within file bounds
	if (obj->elf.e_shoff > obj->len)
	{
		error = "Section header out of bounds";
		return 0;
	}

	//REVIEW: What to do with flags? Spec says should be zero, finding 0x8000??
	//Ignore flags

	//Sanity check header size
	if (obj->elf.e_ehsize != sizeof(Elf32_Ehdr))
	{
		error = "Invalid header size";
		return 0;
	}

	//Ignore program header table entry size and count
	//Assume valid section header table entry size and count

	//Ensure string table is within defined sections
	if (obj->elf.e_shstrndx >= obj->elf.e_shnum)
	{
		error = "String table index out of bounds";
		return 0;
	}

	return 1;
}

static char elf_load_sects(elf_obj_t *obj)
{
	int count = obj->elf.e_shnum;
	size_t len = sizeof(Elf32_Shdr) * count;

	obj->sects = malloc(len);
	if (!obj->sects)
	{
		error = "Failed to alloc space for sections";
		return 0;
	}

	fseek(obj->file, obj->elf.e_shoff, SEEK_SET);
	if (count != (int)fread(obj->sects, sizeof(Elf32_Shdr), count, obj->file))
	{
		error = "Failed to load sections";
		return 0;
	}

	return 1;
}

static char elf_load_shstrings(elf_obj_t *obj)
{
	if (obj->elf.e_shstrndx == SHN_UNDEF)
		return 1;

	//section header strings section
	Elf32_Shdr *sect = &obj->sects[obj->elf.e_shstrndx];
	Elf32_Off location = sect->sh_offset;

	obj->sh_strings = malloc(sect->sh_size);
	if (!obj->sh_strings)
	{
		error = "Failed to alloc space for sh_strings";
		return 0;
	}

	fseek(obj->file, location, SEEK_SET);
	if (sect->sh_size != fread(obj->sh_strings, 1, sect->sh_size, obj->file))
	{
		error = "Failed to load sh_strings";
		return 0;
	}

	return 1;
}

static char save_relocations(int target_sect_idx, Elf32_Rela *relocations, int rela_count, Elf32_Sym *symbols, char *sym_strs, rel_symbol_t *finals)
{
	for (int i = 0; i < rela_count; ++i)
	{
		Elf32_Rela *rela = &relocations[i];
		rel_symbol_t *final = &finals[i];
		
		//Find symbol name
		int sym_idx = ELF32_R_SYM(rela->r_info);
		Elf32_Sym *symbol = &symbols[sym_idx];
		char *name = &sym_strs[symbol->st_name];

		//Copy data
		final->name = strdup(name);
		final->section = target_sect_idx;
		final->offset = rela->r_offset;
		final->rel_type = ELF32_R_TYPE(rela->r_info);
		final->addend = rela->r_addend;
	}

	return 1;
}

static char elf_find_undefined_symbols(elf_obj_t *obj)
{
	for (int i = 0; i < obj->elf.e_shnum; ++i)
	{
		Elf32_Shdr *rela_sect = &obj->sects[i];
		char *sect_name = &obj->sh_strings[rela_sect->sh_name];

		//Skip non relocation sections
		//TODO: Handle SHT_REL
		if (rela_sect->sh_type != SHT_RELA) continue;

		//Skip debug related relocations
		//REVIEW: For now, also skip .eh_frame related relocations
		if (strstr(sect_name, "debug")) continue;
		if (strstr(sect_name, "eh_frame")) continue;

		int rela_count = rela_sect->sh_size / sizeof(Elf32_Rela);
		Elf32_Shdr *sym_sect = &obj->sects[rela_sect->sh_link];
		Elf32_Shdr *symstr_sect = &obj->sects[sym_sect->sh_link];

		//Sanity check entsize
		if (rela_sect->sh_entsize != sizeof(Elf32_Rela) || sym_sect->sh_entsize != sizeof(Elf32_Sym))
		{
			error = "Invalid entsize for rela or symtab";
			return 0;
		}

		
		//Allocate buffers
		Elf32_Rela *relocations = malloc(rela_sect->sh_size);
		Elf32_Sym *symbols = malloc(sym_sect->sh_size);
		char *sym_strs = malloc(symstr_sect->sh_size);

		if (!relocations || !symbols || !sym_strs)
		{
			error = "Failed to alloc space for relocations or symbol strings";
			free(relocations);
			free(symbols);
			free(sym_strs);
			return 0;
		}

		//Read data
		fseek(obj->file, rela_sect->sh_offset, SEEK_SET);
		if (rela_sect->sh_size != fread(relocations, 1, rela_sect->sh_size, obj->file))
		{
			error = "Failed to read relocations";
			free(relocations);
			free(symbols);
			free(sym_strs);
			return 0;
		}
		fseek(obj->file, sym_sect->sh_offset, SEEK_SET);
		if (sym_sect->sh_size != fread(symbols, 1, sym_sect->sh_size, obj->file))
		{
			error = "Failed to read symbols";
			free(relocations);
			free(symbols);
			free(sym_strs);
			return 0;
		}
		fseek(obj->file, symstr_sect->sh_offset, SEEK_SET);
		if (symstr_sect->sh_size != fread(sym_strs, 1, symstr_sect->sh_size, obj->file))
		{
			error = "Failed to read symbol strings";
			free(relocations);
			free(symbols);
			free(sym_strs);
			return 0;
		}

		//Grow (or alloc) relocations vector
		int old_size = obj->rel_count;
		int new_size = old_size + rela_count;
		rel_symbol_t *tmp = realloc(obj->relocations, new_size * sizeof(rel_symbol_t));
		if (!tmp)
		{
			error = "Failed to grow relocations list";
			free(relocations);
			free(symbols);
			free(sym_strs);
			return 0;
		}
		obj->relocations = tmp;
		obj->rel_count = new_size;

		//Interpret data
		char success = save_relocations(i, relocations, rela_count, symbols, sym_strs, &obj->relocations[old_size]);

		//Cleanup
		free(relocations);
		free(symbols);
		free(sym_strs);

		if (!success) return 0;
	}

	return 1;
}

void *dlopen(const char *path, int mode)
{
	(void)mode; //TODO: Not

	elf_obj_t *obj = elf_obj_create(path, &error);
	if (!obj) return NULL;
	
	if (!elf_header_valid(obj) || !elf_header_compatible(obj))
	{
		elf_obj_destroy(obj);
		return NULL;
	}

	if (!elf_load_sects(obj))
	{
		elf_obj_destroy(obj);
		return NULL;
	}

	if (!elf_load_shstrings(obj))
	{
		elf_obj_destroy(obj);
		return NULL;
	}

	if (!elf_find_undefined_symbols(obj))
	{
		elf_obj_destroy(obj);
		return NULL;
	}

	//TODO: Remove
	printf("Selected %d relocations:\n", obj->rel_count);
	for (int i = 0; i < obj->rel_count; ++i)
	{
		rel_symbol_t *sym = &obj->relocations[i];
		printf("R%02d: name=%s rel_type=%d sect=%d off=0x%x addend=0x%x\n",
			i, sym->name, sym->rel_type, sym->section, sym->offset, sym->addend);
	}

	//TODO: Finish
	return obj;
}

int dlclose(void *handle)
{
	elf_obj_destroy((elf_obj_t*)handle);
	return 0;
}

char *dlerror(void)
{
	char *ret = error;
	error = NULL;
	return ret;
}
