#include "data.h"

#include <stdlib.h>

#include "elf.h"

elf_obj_t *elf_obj_create(const char *path, char **error)
{
	elf_obj_t *obj = malloc(sizeof(elf_obj_t));
	if (!obj)
	{
		*error = "Failed to allocate space for elf object.";
		return NULL;
	}
	memset(obj, 0, sizeof(elf_obj_t));

	obj->file = fopen(path, "rb");
	if (!obj->file)
	{
		*error = "Could not open elf file.";
		free(obj);
		return NULL;
	}

	fseek(obj->file, 0, SEEK_END);
	obj->len = ftell(obj->file);
	if (obj->len < sizeof(Elf32_Ehdr))
	{
		*error = "File too small to be an ELF.";
		fclose(obj->file); free(obj);
		return NULL;
	}

	fseek(obj->file, 0, SEEK_SET);
	if (sizeof(Elf32_Ehdr) != fread(&obj->elf, sizeof(Elf32_Ehdr), 1, obj->file))
	{
		*error = "Failed to read ELF header";
		fclose(obj->file); free(obj);
		return NULL;
	}

	return obj;
}
void elf_obj_destroy(elf_obj_t *obj)
{
	if (obj->file) fclose(obj->file);
	if (obj->sects) free(obj->sects);
	if (obj->sh_strings) free(obj->sh_strings);
	if (obj->relocations) free(obj->relocations);
	free(obj);
}

elf_exec_t *elf_exec_create(char **error)
{
	elf_exec_t *exec = malloc(sizeof(elf_exec_t));
	if (!exec)
	{
		*error = "Failed to alloc space for elf executable.";
		return NULL;
	}

	exec->symbols = NULL;
	exec->sym_count = 0;

	return exec;
}
void elf_exec_destroy(elf_exec_t *exec)
{
	if (exec->symbols) free(exec->symbols);
	free(exec);
}
