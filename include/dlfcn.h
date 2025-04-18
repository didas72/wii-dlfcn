#ifndef WII_DLFCN_H_
#define WII_DLFCN_H_

#define RTLD_LAZY 0
#define RTLD_NOW 1
//TODO: Set
#define RTLD_GLOBAL 0
//TODO: Set
#define RTLD_LOCAL 0

//TODO: Implement
/// @brief Initializes dlfcn by loading the executable's own symbol table
/// @param own_path The path to the running executable
/// @return 0 on error, 1 on success
char dlinit(char *own_path);
void *dlopen(const char *file, int mode);
int dlclose(void *handle);
char *dlerror(void);
//TODO: Implement
void *dlsym(void *handle, const char *name);

#endif
