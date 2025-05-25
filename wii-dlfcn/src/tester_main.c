#include "dlfcn.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <gccore.h>
#include <ogc/system.h>
#include <wiiuse/wpad.h>
#include <fat.h>

static void dbg_wait(int frames)
{
	while (frames--) VIDEO_WaitVSync();
}

void test()
{
	int result;

	result = dlinit("/apps/wii-dlfcn-test/boot.elf");
	if (result)
	{
		printf("dlinit failed: %s\n", dlerror());
		return;
	}
	printf("dlinit success\n");

	dbg_wait(30);

	void *handle = dlopen("/apps/wii-dlfcn-test/main.o", 0);
	if (!handle)
	{
		printf("dlopen failed: %s\n", dlerror());
		return;
	}
	printf("dlopen success\n");

	dbg_wait(30);

	void *func = dlsym(handle, "print_ptr");
	if (!func)
	{
		char *err = dlerror();
		if (err)
			printf("dlsym returned null: %s\n", err);
		else
			printf("dlsym returned null with no error\n");
		return;
	}
	int *ptr = func;
	printf("dlsym(handle, \"print_ptr\") = %p\n", func);
	printf("*(dlsym(handle, \"print_ptr\")+20) = 0x%x\n", ptr[5]);

	dbg_wait(150);

	int ret = ((int (*)())func)();
	printf("%d = dlsym(handle, \"print_ptr\")()\n", ret);
	printf("dlsym success\n");

	dbg_wait(30);

	result = dlclose(handle);
	if (result)
	{
		printf("dlclose failed: %s\n", dlerror());
		return;
	}
	printf("dlclose success\n");
}

int main()
{
	int frames = 0;
	VIDEO_Init();
	WPAD_Init();
	GXRModeObj *rmode = VIDEO_GetPreferredMode(NULL);
	void *xfb = MEM_K0_TO_K1(SYS_AllocateFramebuffer(rmode));
	console_init(xfb,20,20,rmode->fbWidth,rmode->xfbHeight,rmode->fbWidth*VI_DISPLAY_PIX_SZ);
	VIDEO_Configure(rmode);
	VIDEO_SetNextFramebuffer(xfb);
	VIDEO_SetBlack(false);
	VIDEO_Flush();
	VIDEO_WaitVSync();
	if(rmode->viTVMode & VI_NON_INTERLACE) VIDEO_WaitVSync();

	printf("Starting\n");
	VIDEO_WaitVSync();

	if (!fatInitDefault())
	{
		printf("Failed to init fat default\n");
		while (++frames < 300) VIDEO_WaitVSync();
		return 1;
	}

	test();

	while(++frames < 300)
	{
		u32 pressed = WPAD_ButtonsDown(0);
		if (pressed) exit(0);
		VIDEO_WaitVSync();
	}
}
