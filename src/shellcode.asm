[SECTION .text]
global _start
_start:
        jmp short stringaddress
mystart:
        xor eax, eax    ;clean up the registers
        xor ebx, ebx
        xor edx, edx
        xor ecx, ecx
        mov al, 4       ;syscall 4 means a write
        mov bl, 1       ;stdout is 1
        pop ecx         ;get the address of the string from the stack
        mov dl, 13      ;length of the string
        int 0x80        ;do syscall
        xor eax, eax
        mov al, 1       ;syscall 1=exit (so we exit the shellcode)
        xor ebx,ebx
        int 0x80
stringaddress:
        call mystart    ;puts the address of the string on the stack :)
        db "hello world!"

