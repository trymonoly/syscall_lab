EXTERN direct_syscall:BYTE   ; ����ȫ�ֱ���

.CODE

NtAllocateVirtualMemory PROC
    mov r10, rcx                                    
    mov eax, DWORD PTR direct_syscall+0            
    syscall                                        
    ret                                             
NtAllocateVirtualMemory ENDP                        

NtWriteVirtualMemory PROC
   mov r10, rcx                                    
    mov eax, DWORD PTR direct_syscall+16             
    syscall                                        
    ret             ; ��ת�� sysAddress
NtWriteVirtualMemory ENDP

NtCreateThreadEx PROC
    mov r10, rcx
    mov eax, DWORD PTR direct_syscall+32           ; ���� wNtFunctionSSN
    syscall                                         ; Execute syscall.
    ret               ; ��ת�� sysAddress
NtCreateThreadEx ENDP

NtWaitForSingleObject PROC
    mov r10, rcx
    mov eax, DWORD PTR direct_syscall+48           ; ���� wNtFunctionSSN
    syscall                                         ; Execute syscall.
    ret               ; ��ת�� sysAddress
NtWaitForSingleObject ENDP

END
