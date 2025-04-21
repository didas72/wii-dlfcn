#include "data.h"

#include <stdlib.h>

#include <sus/ivector.h>

#include "elf.h"

elf_rel_t *elf_rel_create(const char *path, char **error)
{
	elf_rel_t *obj = malloc(sizeof(elf_rel_t));
	if (!obj)
	{
		*error = "Failed to allocate space for ELF object.";
		return NULL;
	}
	memset(obj, 0, sizeof(elf_rel_t));

	obj->elf.file = fopen(path, "rb");
	if (!obj->elf.file)
	{
		*error = "Could not open ELF file.";
		free(obj);
		return NULL;
	}

	fseek(obj->elf.file, 0, SEEK_END);
	long len = ftell(obj->elf.file);
	if (len < (long)sizeof(Elf32_Ehdr))
	{
		*error = "File too small to be an ELF.";
		fclose(obj->elf.file); free(obj);
		return NULL;
	}

	fseek(obj->elf.file, 0, SEEK_SET);
	if (1 != fread(&obj->elf.header, sizeof(Elf32_Ehdr), 1, obj->elf.file))
	{
		*error = "Failed to read ELF header.";
		fclose(obj->elf.file); free(obj);
		return NULL;
	}

	obj->relocations = ivector_create(sizeof(rel_symbol_t));
	obj->symbols = ivector_create(sizeof(def_symbol_t));
	if (!obj->relocations || !obj->symbols)
	{
		*error = "Failed to allocate relocation or symbol vectors.";
		ivector_destroy(obj->relocations);
		ivector_destroy(obj->symbols);
		fclose(obj->elf.file); free(obj);
		return NULL;
	}

	return obj;
}
void elf_rel_destroy(elf_rel_t *obj)
{
	if (obj->elf.file) fclose(obj->elf.file);
	if (obj->elf.sects) free(obj->elf.sects);
	if (obj->elf.sh_strings) free(obj->elf.sh_strings);
	if (obj->relocations) ivector_destroy(obj->relocations);
	if (obj->symbols) ivector_destroy(obj->symbols);
	free(obj);
}

elf_exec_t *elf_exec_create(const char *path, char **error)
{
	elf_exec_t *exec = malloc(sizeof(elf_exec_t));
	if (!exec)
	{
		*error = "Failed to alloc space for ELF executable.";
		return NULL;
	}
	memset(exec, 0, sizeof(elf_exec_t));

	exec->elf.file = fopen(path, "rb");
	if (!exec->elf.file)
	{
		*error = "Could not open ELF file.";
		free(exec);
		return NULL;
	}

	fseek(exec->elf.file, 0, SEEK_END);
	long len = ftell(exec->elf.file);
	if (len < (long)sizeof(Elf32_Ehdr))
	{
		*error = "File too small to be an ELF.";
		fclose(exec->elf.file); free(exec);
		return NULL;
	}

	fseek(exec->elf.file, 0, SEEK_SET);
	if (1 != fread(&exec->elf.header, sizeof(Elf32_Ehdr), 1, exec->elf.file))
	{
		*error = "Failed to read ELF header.";
		fclose(exec->elf.file); free(exec);
		return NULL;
	}

	exec->symbols = ivector_create(sizeof(def_symbol_t));
	if (!exec->symbols)
	{
		*error = "Failed to allocate symbol vector.";
		ivector_destroy(exec->symbols);
		fclose(exec->elf.file); free(exec);
		return NULL;
	}

	return exec;
}
void elf_exec_destroy(elf_exec_t *exec)
{
	if (exec->elf.file) fclose(exec->elf.file);
	if (exec->elf.sects) free(exec->elf.sects);
	if (exec->elf.sh_strings) free(exec->elf.sh_strings);
	if (exec->symbols) ivector_destroy(exec->symbols);
	free(exec);
}
