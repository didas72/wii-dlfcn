#include "dlfcn.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <sus/hashes.h>
#include <sus/ivector.h>
#include <sus/hashset.h>

#include "data.h"
#include "elf.h"
#include "relocations.h"

static char *error = NULL;
static elf_exec_t *self = NULL;
static hashset_t *loaded_relocatables = NULL;

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

static int compute_symbol_addresses(elf_rel_t *obj)
{//TODO: Adjust to allow multiple .text and .data segments
	size_t sym_count = ivector_get_count(obj->symbols);

	for (size_t i = 0; i < sym_count; ++i)
	{
		def_symbol_t* sym = ivector_get(obj->symbols, i);
		Elf32_Shdr *sect = &obj->elf.sects[sym->section];
		char *sect_name = &obj->elf.sh_strings[sect->sh_name];
		if (!strcmp(".text", sect_name))
		{
			sym->address = (char*)obj->sect_text + sym->value;
			continue;
		}
		if (!strcmp(".data", sect_name))
		{
			sym->address = (char*)obj->sect_data + sym->value;
			continue;
		}
		if (!strcmp(".sdata", sect_name))
		{
			sym->address = (char*)obj->sect_sdata + sym->value;
			continue;
		}

		if (strcmp(sym->name, sect_name))
			printf("No address for symbol '%s' of '%s'\n", sym->name, sect_name);
		sym->address = NULL;
	}

	return 1;
}

static int load_needed_sections(elf_rel_t *obj)
{//TODO: Adjust to allow multiple .text, .data and .sdata segments
	//TODO: Loading .rodata* [aligned] not solved yet, as it .rodata still comes separated
	Elf32_Shdr *sect_text = NULL;
	Elf32_Shdr *sect_data = NULL;
	Elf32_Shdr *sect_sdata = NULL;

	//Find relevant sections
	for (int i = 0; i < obj->elf.header.e_shnum; ++i)
	{
		Elf32_Shdr *sect = &obj->elf.sects[i];
		char *name = &obj->elf.sh_strings[sect->sh_name];
		if (!strcmp(".text", name))
		{
			sect_text = sect;
			continue;
		}
		if (!strcmp(".data", name))
		{
			sect_data = sect;
			continue;
		}
		if (!strcmp(".sdata", name))
		{
			sect_sdata = sect;
			continue;
		}
	}

	if (!sect_text || !sect_data || !sect_sdata)
	{
		error = "Could not find .text, .data or .sdata";
		return 0;
	}

	obj->sect_text = aligned_alloc(sect_text->sh_addralign, sect_text->sh_size);
	obj->sect_data = aligned_alloc(sect_data->sh_addralign, sect_data->sh_size);
	obj->sect_sdata = aligned_alloc(sect_sdata->sh_addralign, sect_sdata->sh_size);

	if (!obj->sect_text || !obj->sect_data || !obj->sect_sdata)
	{
		error = "Failed to allocate memory for sections";
		goto _load_needed_sections_error;
	}

	fseek(obj->elf.file, sect_text->sh_offset, SEEK_SET);
	if (sect_text->sh_size != fread(obj->sect_text, 1, sect_text->sh_size, obj->elf.file))
	{
		error = "Failed to load .text";
		goto _load_needed_sections_error;
	}
	fseek(obj->elf.file, sect_data->sh_offset, SEEK_SET);
	if (sect_data->sh_size != fread(obj->sect_data, 1, sect_data->sh_size, obj->elf.file))
	{
		error = "Failed to load .data";
		goto _load_needed_sections_error;
	}
	fseek(obj->elf.file, sect_sdata->sh_offset, SEEK_SET);
	if (sect_sdata->sh_size != fread(obj->sect_sdata, 1, sect_sdata->sh_size, obj->elf.file))
	{
		error = "Failed to load .sdata";
		goto _load_needed_sections_error;
	}

	compute_symbol_addresses(obj);

	return 1;

_load_needed_sections_error:
	free(obj->sect_text); obj->sect_text = NULL;
	free(obj->sect_data); obj->sect_data = NULL;
	return 0;
}

static int apply_relocation(elf_rel_t *obj, rel_symbol_t *relocation, def_symbol_t *symbol)
{
	int place = (int)&((char*)obj->sect_text)[relocation->offset];

	int sym = (int)symbol->value;
	int *target = (int*)place;
	int addend = relocation->addend;

	printf("Relocation of '%s' at %p with %p\n", symbol->name, (void*)target, (void*)sym);

	switch (relocation->rel_type)
	{
		case R_PPC_REL24:
			RELOCATE_REL24(target, sym, place, addend);
			break;

		case R_PPC_ADDR16_HA:
			RELOCATE_ADDR16_HA(((uint16_t*)target), sym, addend);
			break;

		case R_PPC_ADDR16_LO:
			RELOCATE_ADDR16_LO(((uint16_t*)target), sym, addend);
			break;

		//TODO: Other relocations

		default:
			error = "Unsupported relocation type";
			return 0;
	}

	return 1;
}

static int apply_relocations(elf_rel_t *obj)
{
	size_t rel_count = ivector_get_count(obj->relocations);
	printf("Matching %d relocations:\n", rel_count);
	for (size_t i = 0; i < rel_count; ++i)
	{
		rel_symbol_t *rel = ivector_get(obj->relocations, i);;
		def_symbol_t *sym = NULL;
		ivector_t *local_syms = obj->symbols;
		size_t lsym_count = ivector_get_count(local_syms);
		ivector_t *global_syms = self->symbols;
		size_t gsym_count = ivector_get_count(global_syms);

		//Find matching symbol //OPTIMIZE: Hashtable
		for (size_t j = 0; j < lsym_count && sym == NULL; ++j)
		{
			def_symbol_t* lsym = ((def_symbol_t*)ivector_get(local_syms, j));
			if (strcmp(lsym->name, rel->name))
				continue;
			
			sym = lsym;
			printf("[LOCAL] ");
		}
		for (size_t j = 0; j < gsym_count && sym == NULL; ++j)
		{
			def_symbol_t* gsym = ((def_symbol_t*)ivector_get(global_syms, j));
			if (strcmp(gsym->name, rel->name))
				continue;
			
			sym = gsym;
			printf("[GLOBAL] ");
		}

		if (!sym)
			return 0;

		printf("Matched rel/sym %s\n", rel->name);

		if (!strcmp(rel->name, "malloc"))
		{
			printf("Malloc matched to %p (real %p)\n", sym->address, (void*)&malloc);
		}

		if (!apply_relocation(obj, rel, sym))
			return 0;
	}

	return 1;
}

static int compute_own_symbols(elf_exec_t *exec)
{
	size_t sym_count = ivector_get_count(exec->symbols);

	for (size_t i = 0; i < sym_count; ++i)
	{//REVIEW: Currently relies on the hope that elf2dol will keep .text as the first section and that all needed functions are under it
		def_symbol_t* sym = ivector_get(exec->symbols, i);
		Elf32_Shdr *sect = &exec->elf.sects[sym->section];
		char *sect_name = &exec->elf.sh_strings[sect->sh_name];
		if (!strcmp(".text", sect_name))
		{
			sym->address = (void*)sym->value;
			if (!strcmp("malloc", sym->name))
				printf("Setting own malloc to %p (real %p)\n", sym->address, (void*)&malloc);
			continue;
		}
		if (!strcmp(".data", sect_name))
		{
			sym->address = (void*)sym->value;
			continue;
		}
		if (!strcmp(".sdata", sect_name))
		{
			sym->address = (void*)sym->value;
			continue;
		}
		if (!strcmp(".init", sect_name) || !strcmp(".fini", sect_name)
			|| !strcmp(".rodata", sect_name) || !strcmp(".eh_frame_hdr", sect_name)
			|| !strcmp(".sdata2", sect_name) || !strcmp(".eh_frame", sect_name)
			|| !strcmp(".init", sect_name) || !strcmp(".fini", sect_name)
			|| !strcmp(".got2", sect_name) || !strcmp(".ctors", sect_name)
			|| !strcmp(".dtors", sect_name) || !strcmp(".sbss", sect_name)
			|| !strcmp(".bss", sect_name) || !strcmp(".comment", sect_name)
			|| !strcmp(".gnu.attributes", sect_name) || !strcmp(".debug_aranges", sect_name)
			|| !strcmp(".debug_info", sect_name) || !strcmp(".debug_abbrev", sect_name)
			|| !strcmp(".debug_line", sect_name) || !strcmp(".debug_str", sect_name)
			|| !strcmp(".debug_loclists", sect_name) || !strcmp(".debug_rnglists", sect_name)
			|| !strcmp(".symtab", sect_name) || !strcmp(".strtab", sect_name)
			|| !strcmp(".shstrtab", sect_name))
			continue;

		printf("No address for own symbol '%s' of '%s'\n", sym->name, sect_name);
		sym->address = NULL;
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
		goto _dlinit_error;

	if (!elf_load_sects(&exec->elf))
		goto _dlinit_error;
	
	if (!elf_load_shstrings(&exec->elf))
		goto _dlinit_error;

	if (!elf_find_defined_symbols(exec))
		goto _dlinit_error;

	if (!compute_own_symbols(exec))
		goto _dlinit_error;

	self = exec;
	loaded_relocatables = hashset_create(hash_str, compare_str);
	return 0;

_dlinit_error:
	elf_exec_destroy(exec);
	return 1;
}

void *dlopen(const char *path, int mode)
{
	(void)mode; //TODO: Not

	elf_rel_t *obj = elf_rel_create(path, &error);
	if (!obj) return NULL;
	
	if (!elf_rel_valid(obj))
		goto _dlopen_error;

	if (!elf_load_sects(&obj->elf))
		goto _dlopen_error;

	if (!elf_load_shstrings(&obj->elf))
		goto _dlopen_error;

	if (!elf_find_local_symbols(obj))
		goto _dlopen_error;

	if (!elf_find_relocations(obj))
		goto _dlopen_error;

	if (!load_needed_sections(obj))
		goto _dlopen_error;

	//TODO: Finish implementing. Must:
	//Reserve .bss* [aligned]
	
	//Apply relocations
	if (!apply_relocations(obj))
		goto _dlopen_error;

	hashset_add(loaded_relocatables, obj);

	return obj;

_dlopen_error:
	elf_rel_destroy(obj);
	return NULL;
}

int dlclose(void *handle)
{
	if (!hashset_contains(loaded_relocatables, handle))
	{
		error = "Invalid handle";
		return 1;
	}

	elf_rel_destroy((elf_rel_t*)handle);
	return 0;
}

char *dlerror(void)
{
	char *ret = error;
	error = NULL;
	return ret;
}

void *dlsym(void *ptr, const char *name)
{
	elf_rel_t *handle = (elf_rel_t*)ptr;
	if (!hashset_contains(loaded_relocatables, handle))
	{
		error = "Invalid handle";
		return NULL;
	}

	size_t sym_count = ivector_get_count(handle->symbols);
	for (size_t i = 0; i < sym_count; ++i)
	{
		def_symbol_t *sym = (def_symbol_t*)ivector_get(handle->symbols, i);

		if (!strcmp(sym->name, name))
			return sym->address;
	}

	error = "Symbol not found";
	return NULL;
}
