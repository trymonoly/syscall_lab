EXTERN direct_syscall:BYTE   ; 声明全局变量

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
    ret             ; 跳转到 sysAddress
NtWriteVirtualMemory ENDP

NtCreateThreadEx PROC
    mov r10, rcx
    mov eax, DWORD PTR direct_syscall+32           ; 访问 wNtFunctionSSN
    syscall                                         ; Execute syscall.
    ret               ; 跳转到 sysAddress
NtCreateThreadEx ENDP

NtWaitForSingleObject PROC
    mov r10, rcx
    mov eax, DWORD PTR direct_syscall+48           ; 访问 wNtFunctionSSN
    syscall                                         ; Execute syscall.
    ret               ; 跳转到 sysAddress
NtWaitForSingleObject ENDP

END
