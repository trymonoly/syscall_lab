EXTERN direct_syscall:BYTE   ; ����ȫ�ֱ���

.CODE

NtAllocateVirtualMemory PROC
    mov r10, rcx                                   
    mov eax, DWORD PTR direct_syscall+0            ; ���� wNtFunctionSSN
    jmp QWORD PTR [direct_syscall+8]               ; ��ת�� sysAddress
NtAllocateVirtualMemory ENDP                        

NtWriteVirtualMemory PROC
    mov r10, rcx
    mov eax, DWORD PTR direct_syscall+16           ; ���� wNtFunctionSSN
    jmp QWORD PTR [direct_syscall+24]              ; ��ת�� sysAddress
NtWriteVirtualMemory ENDP

NtCreateThreadEx PROC
    mov r10, rcx
    mov eax, DWORD PTR direct_syscall+32           ; ���� wNtFunctionSSN
    jmp QWORD PTR [direct_syscall+40]              ; ��ת�� sysAddress
NtCreateThreadEx ENDP

NtWaitForSingleObject PROC
    mov r10, rcx
    mov eax, DWORD PTR direct_syscall+48           ; ���� wNtFunctionSSN
    jmp QWORD PTR [direct_syscall+56]              ; ��ת�� sysAddress
NtWaitForSingleObject ENDP

END
