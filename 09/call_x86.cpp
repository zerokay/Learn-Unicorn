#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
typedef int (* fsign1) (char * sign_data,char * outbuffer);
int main()
{
	char buffer[100] = {0};
	FILE * fp = fopen("libnative-lib.so","rb");
	size_t size = 0;
	fseek(fp,0,SEEK_END);
	size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	
	char * image = new char[size];
	fread(image, size, 1, fp);
	fclose(fp);
	
	// VirtualProtect
	DWORD old;
	VirtualProtect(image, size, PAGE_EXECUTE_READWRITE, &old);
	
	fsign1 Sign1 = (fsign1)&image[0xA6E0];
	
	//fix got
	DWORD *tea_encrypt_got;
	DWORD *sprintf_got;
	DWORD * __stack_chk_guard_ptr;
	
	tea_encrypt_got = (DWORD *)&image[0x3BD94];
	sprintf_got = (DWORD *)&image[0x3BD98];
	
	__stack_chk_guard_ptr = (DWORD *)&image[0x3BD04];
	*tea_encrypt_got = (DWORD)&image[0xA0A0];
	*sprintf_got = (DWORD)sprintf;
	
	*__stack_chk_guard_ptr = (DWORD)image; 
	
	Sign1("123", buffer);
	printf("sign data:%s ",buffer);
	
	return 0;
}
