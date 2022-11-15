#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <windows.h>

typedef int(*func_sign_lv1) (char* a1, char* buffer);

int main() {
	char buffer[100] = { 0 };

	FILE* fp = fopen("libnative-lib.so", "rb"); // 打开so文件

	// 获取文件长度
	size_t file_size = 0;
	fseek(fp, 0, SEEK_END);                    // 移动到文件尾部
	file_size = ftell(fp);                     // 获取文件长度
	printf("File Size is: %d\n", file_size);

	// 复原
	fseek(fp, 0, SEEK_SET);                    // 移动到文件开始

	// 读取so内容
	char* image_address = new char[file_size];
	fread(image_address, file_size, 1, fp);    // 读取文件到缓冲区
	fclose(fp);                                // 关闭文件

	
	// 修改内存属性
	DWORD old;                                // 保存旧的保护方式
	VirtualProtect(image_address, file_size, PAGE_EXECUTE_READWRITE, &old);

	// fix got table
	// 修复栈保护机制
	DWORD stack_check = 123;
	DWORD* got_stack_chk_guard_ptr = (DWORD*)&image_address[0x3BD04];
	*got_stack_chk_guard_ptr = (DWORD)&stack_check;

	// 修复tea_encrypt
	DWORD* got_tea_encrypt = (DWORD*)&image_address[0x3BD94];
	*got_tea_encrypt = (DWORD)&image_address[0xA0A0];

	// 修复sprintf
	DWORD* got_sprintf     = (DWORD*)&image_address[0x3BD98];
	*got_sprintf     = (DWORD)sprintf;
	
	// 调用sign_lv1
	func_sign_lv1 sign_lv1 = (func_sign_lv1)&image_address[0xA6E0];

	sign_lv1((char*)"123", buffer);
	printf("Sign data: %s", buffer);

	return 0;
}
