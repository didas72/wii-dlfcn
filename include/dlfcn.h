#ifndef WII_DLFCN_H_
#define WII_DLFCN_H_

#define RTLD_LAZY 0
#define RTLD_NOW 1
//TODO: Set
#define RTLD_GLOBAL 0
//TODO: Set
#define RTLD_LOCAL 0

//TODO: Implement
void *dlopen(const char *file, int mode);
//TODO: Implement
int dlclose(void *handle);
char *dlerror(void);
//TODO: Implement
void *dlsym(void *handle, const char *name);

#endif
