#include "dlfcn.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <sus/ivector.h>

#include "data.h"
#include "elf.h"
#include "mmu_dump.h"

static char *error = NULL;
static elf_exec_t *self = NULL;

static int elf_valid_compat(Elf32_Ehdr *elf)
{
	//Check ELF magic
	if (elf->e_ident[EI_MAG0] != ELFMAG0 ||
		elf->e_ident[EI_MAG1] != ELFMAG1 ||
		elf->e_ident[EI_MAG2] != ELFMAG2 ||
		elf->e_ident[EI_MAG3] != ELFMAG3)
	{
		error = "Invalid ELF magic";
		return 0;
	}

	//Require 32-bit, Big Endian, ELF version values
	if (elf->e_ident[EI_CLASS] != ELFCLASS32 ||
		elf->e_ident[EI_DATA] != ELFDATA2MSB || 
		elf->e_ident[EI_VERSION] != EV_CURRENT)
	{
		error = "Invalid IDENT values";
		return 0;
	}

	//Require PPC
	if (elf->e_machine != EM_PPC)
	{
		error = "Invalid target machine";
		return 0;
	}

	//Require current ELF version
	if (elf->e_version != EV_CURRENT)
	{
		error = "Invalid ELF version";
		return 0;
	}

	return 1;
}

static int elf_rel_valid(elf_rel_t *obj)
{
	if (!elf_valid_compat(&obj->elf.header))
		return 0;
	
	//Require object file
	if (obj->elf.header.e_type != ET_REL)
	{
		error = "Unsupported ELF type, must be ET_REL (object file)";
		return 0;
	}

	return 1;
}

static int elf_exec_valid(elf_exec_t *exec)
{
	if (!elf_valid_compat(&exec->elf.header))
		return 0;
	
	//Require object file
	if (exec->elf.header.e_type != ET_EXEC)
	{
		error = "Unsupported ELF type, must be ET_EXEC (executable file)";
		return 0;
	}

	return 1;
}

static int elf_load_sects(elf_file_t *elf)
{
	int count = elf->header.e_shnum;
	size_t len = sizeof(Elf32_Shdr) * count;

	elf->sects = malloc(len);
	if (!elf->sects)
	{
		error = "Failed to alloc space for sections";
		return 0;
	}

	fseek(elf->file, elf->header.e_shoff, SEEK_SET);
	if (count != (int)fread(elf->sects, sizeof(Elf32_Shdr), count, elf->file))
	{
		error = "Failed to load sections";
		return 0;
	}

	return 1;
}

static int elf_load_shstrings(elf_file_t *elf)
{
	if (elf->header.e_shstrndx == SHN_UNDEF)
		return 1;

	//section header strings section
	Elf32_Shdr *sect = &elf->sects[elf->header.e_shstrndx];
	Elf32_Off location = sect->sh_offset;

	elf->sh_strings = malloc(sect->sh_size);
	if (!elf->sh_strings)
	{
		error = "Failed to alloc space for sh_strings";
		return 0;
	}

	fseek(elf->file, location, SEEK_SET);
	if (sect->sh_size != fread(elf->sh_strings, 1, sect->sh_size, elf->file))
	{
		error = "Failed to load sh_strings";
		return 0;
	}

	return 1;
}

static int save_symbols(elf_file_t *elf, Elf32_Sym *symbols, int sym_count, char *sym_strs, ivector_t *finals)
{
	for (int i = 1; i < sym_count; ++i)
	{
		Elf32_Sym *symbol = &symbols[i];
		def_symbol_t final = { 0 };
		int type = ELF32_ST_TYPE(symbol->st_info);

		//Skip unneeded symbols
		if (type == STT_NOTYPE || type == STT_FILE) continue;

		//Find symbol name
		char *name = type == STT_SECTION ? &elf->sh_strings[elf->sects[symbol->st_shndx].sh_name] : &sym_strs[symbol->st_name];

		//Copy data
		final.name = strdup(name);
		final.value = symbol->st_value;
		final.bind = ELF32_ST_BIND(symbol->st_info);
		final.type = type;
		final.section = symbol->st_shndx;

		//Save symbol
		ivector_append(finals, &final);
	}

	ivector_trim(finals);
	return 1;
}

static int elf_find_defined_symbols(elf_exec_t *exec)
{
	//Skip NULL section
	for (int i = 1; i < exec->elf.header.e_shnum; ++i)
	{
		Elf32_Shdr *sym_sect = &exec->elf.sects[i];

		//Skip non symbol sections
		if (sym_sect->sh_type != SHT_SYMTAB) continue;

		int sym_count = sym_sect->sh_size / sizeof(Elf32_Sym);
		Elf32_Shdr *symstr_sect = &exec->elf.sects[sym_sect->sh_link];

		//Sanity check entsize
		if (sym_sect->sh_entsize != sizeof(Elf32_Sym))
		{
			error = "Invalid entsize for symtab";
			return 0;
		}

		//Allocate buffers
		Elf32_Sym *symbols = malloc(sym_sect->sh_size);
		char *sym_strs = malloc(symstr_sect->sh_size);

		if (!symbols || !sym_strs)
		{
			error = "Failed to alloc space for symbols or symbol strings";
			free(symbols);
			free(sym_strs);
			return 0;
		}

		//Read data
		fseek(exec->elf.file, sym_sect->sh_offset, SEEK_SET);
		if (sym_sect->sh_size != fread(symbols, 1, sym_sect->sh_size, exec->elf.file))
		{
			error = "Failed to read symbols";
			free(symbols);
			free(sym_strs);
			return 0;
		}
		fseek(exec->elf.file, symstr_sect->sh_offset, SEEK_SET);
		if (symstr_sect->sh_size != fread(sym_strs, 1, symstr_sect->sh_size, exec->elf.file))
		{
			error = "Failed to read symbol strings";
			free(symbols);
			free(sym_strs);
			return 0;
		}

		//Interpret data (skipping NULL symbol)
		char success = save_symbols(&exec->elf, &symbols[1], sym_count - 1, sym_strs, exec->symbols);

		//Cleanup
		free(symbols);
		free(sym_strs);

		if (!success) return 0;
	}

	return 1;
}

static int save_relocations(elf_file_t *elf, int target_sect_idx, Elf32_Rela *relocations, int rela_count, Elf32_Sym *symbols, char *sym_strs, ivector_t *finals)
{
	for (int i = 0; i < rela_count; ++i)
	{
		Elf32_Rela *rela = &relocations[i];
		rel_symbol_t final = { 0 };
		
		//Find symbol name
		int sym_idx = ELF32_R_SYM(rela->r_info);
		Elf32_Sym *symbol = &symbols[sym_idx];
		char *name = ELF32_ST_TYPE(symbol->st_info) == STT_SECTION ? &elf->sh_strings[elf->sects[symbol->st_shndx].sh_name] : &sym_strs[symbol->st_name];

		//Copy data
		final.name = strdup(name);
		final.section = target_sect_idx;
		final.offset = rela->r_offset;
		final.rel_type = ELF32_R_TYPE(rela->r_info);
		final.addend = rela->r_addend;

		//Save relocation
		ivector_append(finals, &final);
	}

	ivector_trim(finals);
	return 1;
}

static int elf_find_relocations(elf_rel_t *obj)
{
	//Skip NULL section
	for (int i = 1; i < obj->elf.header.e_shnum; ++i)
	{
		Elf32_Shdr *rela_sect = &obj->elf.sects[i];
		char *sect_name = &obj->elf.sh_strings[rela_sect->sh_name];

		//Skip non relocation sections (SHT_REL not used in powerpc-eabi-none)
		if (rela_sect->sh_type != SHT_RELA) continue;

		//Skip debug related relocations
		//REVIEW: For now, also skip .eh_frame related relocations
		if (strstr(sect_name, "debug")) continue;
		if (strstr(sect_name, "eh_frame")) continue;

		int rela_count = rela_sect->sh_size / sizeof(Elf32_Rela);
		Elf32_Shdr *sym_sect = &obj->elf.sects[rela_sect->sh_link];
		Elf32_Shdr *symstr_sect = &obj->elf.sects[sym_sect->sh_link];

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
		fseek(obj->elf.file, rela_sect->sh_offset, SEEK_SET);
		if (rela_sect->sh_size != fread(relocations, 1, rela_sect->sh_size, obj->elf.file))
		{
			error = "Failed to read relocations";
			free(relocations);
			free(symbols);
			free(sym_strs);
			return 0;
		}
		fseek(obj->elf.file, sym_sect->sh_offset, SEEK_SET);
		if (sym_sect->sh_size != fread(symbols, 1, sym_sect->sh_size, obj->elf.file))
		{
			error = "Failed to read symbols";
			free(relocations);
			free(symbols);
			free(sym_strs);
			return 0;
		}
		fseek(obj->elf.file, symstr_sect->sh_offset, SEEK_SET);
		if (symstr_sect->sh_size != fread(sym_strs, 1, symstr_sect->sh_size, obj->elf.file))
		{
			error = "Failed to read symbol strings";
			free(relocations);
			free(symbols);
			free(sym_strs);
			return 0;
		}

		//Interpret data
		char success = save_relocations(&obj->elf, i, relocations, rela_count, symbols, sym_strs, obj->relocations);

		//Cleanup
		free(relocations);
		free(symbols);
		free(sym_strs);

		if (!success) return 0;
	}

	return 1;
}

static int elf_find_local_symbols(elf_rel_t *obj)
{
	//Skip NULL section
	for (int i = 1; i < obj->elf.header.e_shnum; ++i)
	{
		Elf32_Shdr *sym_sect = &obj->elf.sects[i];

		//Skip non symbol sections
		if (sym_sect->sh_type != SHT_SYMTAB) continue;

		int sym_count = sym_sect->sh_size / sizeof(Elf32_Sym);
		Elf32_Shdr *symstr_sect = &obj->elf.sects[sym_sect->sh_link];

		//Sanity check entsize
		if (sym_sect->sh_entsize != sizeof(Elf32_Sym))
		{
			error = "Invalid entsize for symtab";
			return 0;
		}

		//Allocate buffers
		Elf32_Sym *symbols = malloc(sym_sect->sh_size);
		char *sym_strs = malloc(symstr_sect->sh_size);

		if (!symbols || !sym_strs)
		{
			error = "Failed to alloc space for symbols or symbol strings";
			free(symbols);
			free(sym_strs);
			return 0;
		}

		//Read data
		fseek(obj->elf.file, sym_sect->sh_offset, SEEK_SET);
		if (sym_sect->sh_size != fread(symbols, 1, sym_sect->sh_size, obj->elf.file))
		{
			error = "Failed to read symbols";
			free(symbols);
			free(sym_strs);
			return 0;
		}
		fseek(obj->elf.file, symstr_sect->sh_offset, SEEK_SET);
		if (symstr_sect->sh_size != fread(sym_strs, 1, symstr_sect->sh_size, obj->elf.file))
		{
			error = "Failed to read symbol strings";
			free(symbols);
			free(sym_strs);
			return 0;
		}

		//Interpret data (skipping NULL symbol)
		char success = save_symbols(&obj->elf, &symbols[1], sym_count - 1, sym_strs, obj->symbols);

		//Cleanup
		free(symbols);
		free(sym_strs);

		if (!success) return 0;
	}

	return 1;
}

static int load_needed_sections(elf_rel_t *obj)
{
	//TODO: Implement:
	//Load .text* [aligned]
	//Load .data* and .rodata* [aligned]
	(void)obj;
	return 1;
}

static int apply_relocations(elf_rel_t *obj)
{
	rel_symbol_t *relocations = obj->relocations->data;

	printf("Matching %d relocations:\n", obj->relocations->count);
	for (size_t i = 0; i < obj->relocations->count; ++i)
	{
		rel_symbol_t *rel = &relocations[i];
		def_symbol_t *sym = NULL;
		def_symbol_t *local_syms = obj->symbols->data;
		def_symbol_t *global_syms = self->symbols->data;

		//Find matching symbol //TODO: Hashtable
		for (size_t j = 0; j < obj->symbols->count && !sym; ++j)
		{
			if (strcmp(local_syms[j].name, rel->name))
				continue;
			
			sym = &local_syms[j];
		}
		for (size_t j = 0; j < self->symbols->count && !sym; ++j)
		{
			if (strcmp(global_syms[j].name, rel->name))
				continue;
			
			sym = &global_syms[j];
		}

		if (!sym)
			return 0;

		printf("Matched rel/sym %s\n", rel->name);

		//TODO: Actually apply relocation
	}

	return 1;
}

int dlinit(char *own_path)
{
	error = NULL;

	if (self)
	{
		error = "Already initialized wii-dlfcn";
		return 1;
	}

	elf_exec_t *exec = elf_exec_create(own_path, &error);
	if (!exec) return 1;

	if (!elf_exec_valid(exec))
	{
		elf_exec_destroy(exec);
		return 1;
	}

	if (!elf_load_sects(&exec->elf))
	{
		elf_exec_destroy(exec);
		return 1;
	}
	
	if (!elf_load_shstrings(&exec->elf))
	{
		elf_exec_destroy(exec);
		return 1;
	}

	if (!elf_find_defined_symbols(exec))
	{
		elf_exec_destroy(exec);
		return 1;
	}

	//TODO: Remove
	def_symbol_t *global_symbols = exec->symbols->data;
	printf("Found %d symbols, showing some functions:\n", exec->symbols->count);
	int printed = 0;
	for (size_t i = 0; i < exec->symbols->count && printed < 8; ++i)
	{
		def_symbol_t *sym = &global_symbols[i];

		if (sym->type != STT_FUNC)
			continue;

		++printed;
		printf("S%02d: name=%s value=0x%x bind=%d type=%d section=%d\n",
			i, sym->name, sym->value, sym->bind, sym->type, sym->section);
	}

	self = exec;
	return 0;
}

void *dlopen(const char *path, int mode)
{
	error = NULL;
	(void)mode; //TODO: Not

	elf_rel_t *obj = elf_rel_create(path, &error);
	if (!obj) return NULL;
	
	if (!elf_rel_valid(obj))
	{
		elf_rel_destroy(obj);
		return NULL;
	}

	if (!elf_load_sects(&obj->elf))
	{
		elf_rel_destroy(obj);
		return NULL;
	}

	if (!elf_load_shstrings(&obj->elf))
	{
		elf_rel_destroy(obj);
		return NULL;
	}

	if (!elf_find_local_symbols(obj))
	{
		elf_rel_destroy(obj);
		return NULL;
	}

	if (!elf_find_relocations(obj))
	{
		elf_rel_destroy(obj);
		return NULL;
	}

	//TODO: Remove
	rel_symbol_t *local_symbols = obj->relocations->data;
	printf("Selected %d relocations:\n", obj->relocations->count);
	for (size_t i = 0; i < obj->relocations->count; ++i)
	{
		rel_symbol_t *sym = &local_symbols[i];
		printf("R%02d: name=%s rel_type=%d sect=%d off=0x%x addend=0x%x\n",
			i, sym->name, sym->rel_type, sym->section, sym->offset, sym->addend);
	}

	if (!load_needed_sections(obj))
	{
		elf_rel_destroy(obj);
		return NULL;
	}

	//TODO: Finish implementing. Must:
	//Reserve .bss* [aligned]
	//Match symbols on loaded executable
	
	//Apply relocations
	if (!apply_relocations(obj))
	{
		elf_rel_destroy(obj);
		return NULL;
	}

	return obj;
}

int dlclose(void *handle)
{
	error = NULL;
	elf_rel_destroy((elf_rel_t*)handle);
	return 0;
}

char *dlerror(void)
{
	char *ret = error;
	error = NULL;
	return ret;
}
