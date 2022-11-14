#include <windows.h>
#include <stdio.h>
typedef int(* fsign1) (char *a1, char * buffer);
int main(){
	char buffer[100] = {0};
	FILE * fp = fopen("libnative-lib.so","rb");
	size_t filesize = 0;
	fseek(fp, 0, SEEK_END);
	filesize = ftell(fp); 
	fseek(fp, 0, SEEK_SET);
	
	char * image = new char[filesize];
	fread(image, filesize, 1, fp);
	fclose(fp);
	
	DWORD old;
	VirtualProtect(image, filesize, PAGE_EXECUTE_READWRITE, &old);
	
	//fix got
	DWORD stack_check = 123;
	DWORD * got_tea_encrypt = (DWORD *)&image[0x3BD94];
	DWORD * got_sprintf = (DWORD *)&image[0x3BD98];
	DWORD * got_stack_check = (DWORD *)&image[0x3BD04];
	
	*got_tea_encrypt = (DWORD)&image[0xA0A0];
	*got_sprintf = (DWORD)sprintf;
	*got_stack_check = (DWORD)&stack_check;
		
	fsign1 Sign = (fsign1) &image[0xA6E0];
	
	Sign("123", buffer);
	
	printf("result:%s", buffer);
	return 0;
}
