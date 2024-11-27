#ifndef SYSCALLS_H
#define SYSCALLS_H

#include <Windows.h>

// 定义每个系统调用的信息
typedef struct _FunctionAddress {
    DWORD wNtFunctionSSN;   // SSN (System Service Number)
    UINT_PTR sysAddress;    // 函数地址
} FunctionAddress, * PFunctionAddress;

// 定义所有需要的系统调用
typedef struct _FuncationName {
    FunctionAddress NtAllocateVirtualMemory;
    FunctionAddress NtWriteVirtualMemory;
    FunctionAddress NtCreateThreadEx;
    FunctionAddress NtWaitForSingleObject;
} FuncationName, * PFuncationName;

// 声明全局变量供其他文件和汇编访问
#ifdef __cplusplus
extern "C" {
#endif

    __declspec(dllexport) extern FuncationName direct_syscall; // 导出全局变量

    // 定义 NTSTATUS 类型
    typedef long NTSTATUS;
    typedef NTSTATUS* PNTSTATUS;

    // 系统调用函数的声明
    __declspec(dllexport) NTSTATUS NtAllocateVirtualMemory(
        HANDLE ProcessHandle,    // 进程句柄
        PVOID* BaseAddress,      // 基地址指针
        ULONG_PTR ZeroBits,      // 零位
        PSIZE_T RegionSize,      // 区域大小
        ULONG AllocationType,    // 分配类型
        ULONG Protect            // 内存保护类型
    );

    __declspec(dllexport) NTSTATUS NtWriteVirtualMemory(
        HANDLE ProcessHandle,        // 进程句柄
        PVOID BaseAddress,           // 基地址
        PVOID Buffer,                // 数据缓冲区
        SIZE_T NumberOfBytesToWrite, // 写入字节数
        PULONG NumberOfBytesWritten  // 实际写入字节数
    );

    __declspec(dllexport) NTSTATUS NtCreateThreadEx(
        PHANDLE ThreadHandle,         // 线程句柄
        ACCESS_MASK DesiredAccess,    // 所需访问权限
        PVOID ObjectAttributes,       // 对象属性
        HANDLE ProcessHandle,         // 进程句柄
        PVOID lpStartAddress,         // 线程入口地址
        PVOID lpParameter,            // 参数
        ULONG Flags,                  // 标志
        SIZE_T StackZeroBits,         // 栈零位
        SIZE_T SizeOfStackCommit,     // 栈提交大小
        SIZE_T SizeOfStackReserve,    // 栈保留大小
        PVOID lpBytesBuffer           // 字节缓冲区
    );

    __declspec(dllexport) NTSTATUS NtWaitForSingleObject(
        HANDLE Handle,           // 等待的句柄
        BOOLEAN Alertable,       // 是否可被警报中断
        PLARGE_INTEGER Timeout   // 超时时间
    );

#ifdef __cplusplus
}
#endif

#endif // SYSCALLS_H
