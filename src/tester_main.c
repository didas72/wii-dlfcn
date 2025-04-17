#include "dlfcn.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <gccore.h>
#include <ogc/system.h>
#include <wiiuse/wpad.h>
#include <fat.h>

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

	void *handle = dlopen("/wii-dlfcn/main.o", 0);
	if (!handle)
		printf("%s\n", dlerror());
	else
	{
		printf("Success\n");
		//dlclose(handle);
	}

	while(++frames < 300)
	{
		u32 pressed = WPAD_ButtonsDown(0);
		if (pressed) exit(0);
		VIDEO_WaitVSync();
	}
}
