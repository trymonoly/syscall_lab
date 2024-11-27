#ifndef SYSCALLS_H
#define SYSCALLS_H

#include <Windows.h>

// ����ÿ��ϵͳ���õ���Ϣ
typedef struct _FunctionAddress {
    DWORD wNtFunctionSSN;   // SSN (System Service Number)
    UINT_PTR sysAddress;    // ������ַ
} FunctionAddress, * PFunctionAddress;

// ����������Ҫ��ϵͳ����
typedef struct _FuncationName {
    FunctionAddress NtAllocateVirtualMemory;
    FunctionAddress NtWriteVirtualMemory;
    FunctionAddress NtCreateThreadEx;
    FunctionAddress NtWaitForSingleObject;
} FuncationName, * PFuncationName;

// ����ȫ�ֱ����������ļ��ͻ�����
#ifdef __cplusplus
extern "C" {
#endif

    __declspec(dllexport) extern FuncationName direct_syscall; // ����ȫ�ֱ���

    // ���� NTSTATUS ����
    typedef long NTSTATUS;
    typedef NTSTATUS* PNTSTATUS;

    // ϵͳ���ú���������
    __declspec(dllexport) NTSTATUS NtAllocateVirtualMemory(
        HANDLE ProcessHandle,    // ���̾��
        PVOID* BaseAddress,      // ����ַָ��
        ULONG_PTR ZeroBits,      // ��λ
        PSIZE_T RegionSize,      // �����С
        ULONG AllocationType,    // ��������
        ULONG Protect            // �ڴ汣������
    );

    __declspec(dllexport) NTSTATUS NtWriteVirtualMemory(
        HANDLE ProcessHandle,        // ���̾��
        PVOID BaseAddress,           // ����ַ
        PVOID Buffer,                // ���ݻ�����
        SIZE_T NumberOfBytesToWrite, // д���ֽ���
        PULONG NumberOfBytesWritten  // ʵ��д���ֽ���
    );

    __declspec(dllexport) NTSTATUS NtCreateThreadEx(
        PHANDLE ThreadHandle,         // �߳̾��
        ACCESS_MASK DesiredAccess,    // �������Ȩ��
        PVOID ObjectAttributes,       // ��������
        HANDLE ProcessHandle,         // ���̾��
        PVOID lpStartAddress,         // �߳���ڵ�ַ
        PVOID lpParameter,            // ����
        ULONG Flags,                  // ��־
        SIZE_T StackZeroBits,         // ջ��λ
        SIZE_T SizeOfStackCommit,     // ջ�ύ��С
        SIZE_T SizeOfStackReserve,    // ջ������С
        PVOID lpBytesBuffer           // �ֽڻ�����
    );

    __declspec(dllexport) NTSTATUS NtWaitForSingleObject(
        HANDLE Handle,           // �ȴ��ľ��
        BOOLEAN Alertable,       // �Ƿ�ɱ������ж�
        PLARGE_INTEGER Timeout   // ��ʱʱ��
    );

#ifdef __cplusplus
}
#endif

#endif // SYSCALLS_H
