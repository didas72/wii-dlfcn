#include "dlfcn.h"

#include <stddef.h>

static char *error = NULL;

char *dlerror(void)
{
	char *ret = error;
	error = NULL;
	return ret;
}
