#include "dlfcn.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "elf.h"

typedef struct {
	FILE *file;
	size_t len;
	Elf32_Ehdr elf;
	Elf32_Shdr *sects;
	char *sh_strings;
} elf_obj_t;

typedef struct {
	char **names;
	void **ptrs;
	size_t length;
} symbol_table_t;

static char *error = NULL;

static elf_obj_t *elf_obj_create(const char *path)
{
	elf_obj_t *obj = malloc(sizeof(elf_obj_t));
	if (!obj)
	{
		error = "Failed to allocate space for elf object.";
		return NULL;
	}
	memset(obj, 0, sizeof(elf_obj_t));

	obj->file = fopen(path, "rb");
	if (!obj->file)
	{
		error = "Could not open elf file.";
		free(obj);
		return NULL;
	}

	fseek(obj->file, 0, SEEK_END);
	obj->len = ftell(obj->file);

	if (obj->len < sizeof(Elf32_Ehdr))
	{
		error = "File too small to be an ELF.";
		fclose(obj->file); free(obj);
		return NULL;
	}

	fseek(obj->file, 0, SEEK_SET);
	fread(&obj->elf, sizeof(Elf32_Ehdr), 1, obj->file); //TODO: Error check

	return obj;
}
static void elf_obj_destroy(elf_obj_t *obj)
{
	if (obj->file) fclose(obj->file);
	if (obj->sects) free(obj->sects);
	if (obj->sh_strings) free(obj->sh_strings);
	free(obj);
}

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

	fseek(obj->file, obj->elf.e_shoff, SEEK_SET); //TODO: Error check
	
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

static char elf_show_symtab(elf_obj_t *obj, int idx)
{
	Elf32_Shdr *sect = &obj->sects[idx];
	int ent_count = sect->sh_size / sect->sh_entsize;

	printf("Sect%02d: SYMTAB sym_count=%d STRTAB=%d last_local+1=%d name=%s\n", idx, ent_count, sect->sh_link, sect->sh_info, &obj->sh_strings[sect->sh_name]);

	//Load symbol strings
	Elf32_Shdr *str_sect = &obj->sects[sect->sh_link];
	char *sym_strs = malloc(str_sect->sh_size);
	if (!sym_strs)
	{
		error = "Failed alloc space for SYMTAB symbol strings";
		return 0;
	}
	
	fseek(obj->file, str_sect->sh_offset, SEEK_SET);
	if (str_sect->sh_size != fread(sym_strs, 1, str_sect->sh_size, obj->file))
	{
		error = "Failed to read SYMTAB symbol strings";
		free(sym_strs);
		return 0;
	}

	//Load symbols
	Elf32_Sym *syms = malloc(sect->sh_size);
	if (!syms)
	{
		error = "Failed alloc space for SYMTAB symbols";
		free(sym_strs);
		return 0;
	}

	fseek(obj->file, sect->sh_offset, SEEK_SET);
	if (sect->sh_size != fread(syms, 1, sect->sh_size, obj->file))
	{
		error = "Failed to read SYMTAB symbols";
		free(sym_strs);
		free(syms);
		return 0;
	}

	//Show symbols
	for (int s = 0; s < ent_count; ++s)
	{
		Elf32_Sym *sym = &syms[s];
		printf("Sym%02d: name=%s value=0x%x size=0x%x bind=0x%x type=0x%x\n", s, &sym_strs[sym->st_name], sym->st_value, sym->st_size, ELF32_ST_BIND(sym->st_info), ELF32_ST_TYPE(sym->st_info));
	}

	//Cleanup
	free(syms);
	free(sym_strs);
	return 1;
}

static char elf_show_rela(elf_obj_t *obj, int idx)
{
	Elf32_Shdr *sect = &obj->sects[idx];
	int ent_count = sect->sh_size / sect->sh_entsize;

	printf("Sect%02d: RELA sym_count=%d sym_tab=%d target_sect=%d name=%s\n", idx, ent_count, sect->sh_link, sect->sh_info, &obj->sh_strings[sect->sh_name]);

	Elf32_Rela *syms_rela = malloc(sect->sh_size);
	if (!syms_rela)
	{
		error = "Failed alloc space for RELA symbols";
		return 0;
	}

	fseek(obj->file, sect->sh_offset, SEEK_SET);
	if (sect->sh_size != fread(syms_rela, 1, sect->sh_size, obj->file))
	{
		error = "Failed to read RELA symbols";
		free(syms_rela);
		return 0;
	}

	for (int s = 0; s < ent_count; ++s)
	{
		Elf32_Rela *sym = &syms_rela[s];
		printf("Sym%02d: off=0x%x symbol=%d type=%d addend=0x%x\n", s, sym->r_offset, ELF32_R_SYM(sym->r_info), ELF32_R_TYPE(sym->r_info), sym->r_offset);
	}

	free(syms_rela);
	return 1;
}

static char elf_find_undefined_symbols(elf_obj_t *obj)
{
	int count = obj->elf.e_shnum;
	printf("RELA and SYMTAB sections (out of %d):\n", obj->elf.e_shnum);

	for (int i = 1; i < count; ++i)
	{
		Elf32_Shdr *sect = &obj->sects[i];

		printf("S%02d: type=%d\n", i, sect->sh_type);

		if (sect->sh_type == SHT_SYMTAB)
		{
			if (!elf_show_symtab(obj, i))
				return 0;
			continue;
		}

		if (sect->sh_type != SHT_RELA || !strstr(&obj->sh_strings[sect->sh_name], ".rela.text"))
			continue;

		continue; //TODO: Remove
		if (!elf_show_rela(obj, i))
			return 0;
	}

	//TODO: Finish
	return 1;
}

void *dlopen(const char *path, int mode)
{
	(void)mode; //TODO: Not

	elf_obj_t *obj = elf_obj_create(path);
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
