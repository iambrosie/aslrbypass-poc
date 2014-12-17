CC=gcc

all: shellcode shell badbuf 

shellcode:	shellcode.asm
	nasm -f elf shellcode.asm
	ld -s -o shellcode shellcode.o

shell:	shell.S
	as shell.S -o shell.o
	ld -s -o shell shell.o

realshellcode:	realshellcode.S
	as realshellcode.S -o realshellcode.o
	ld -s -o realshellcode realshellcode.o


badbuf:	vulnerable.c
	$(CC) -g -O0 -m32 -Wall -fno-stack-protector -o badbuf  vulnerable.c


clean:
	rm -f badbuf shellcode.o shellcode realshellcode.o realshellcode shell shello.o
