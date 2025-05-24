#ifndef WII_DLFCN_H_
#define WII_DLFCN_H_

#define RTLD_LAZY 0
#define RTLD_NOW 1

/// @brief Initializes dlfcn by loading the executable's own symbol table
/// @param own_path The path to the running executable
/// @return 0 on error, 1 on success
int dlinit(char *own_path);

void *dlopen(const char *file, int mode);
int dlclose(void *handle);
char *dlerror(void);
void *dlsym(void *handle, const char *name);

#endif
