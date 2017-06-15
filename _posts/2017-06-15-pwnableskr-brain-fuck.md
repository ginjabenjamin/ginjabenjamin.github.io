---
layout: default
category: pwn
tags: [reversing, pwn, writeup]
---
# pwnables.kr/brain fuck
## Purpose: Learning to GOT

Source: [pwnables.kr](http://pwnable.kr/play.php)

Solution: [solve.py](https://ginjabenjamin.github.io/objects/2017-06-15-pwnableskr-brain-fuck/brainfuck-solve.py)

## Challenge
### Type:
Pwn

### File:
```
# file bf
bf: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=190d45832c271de25448cefe52fbd15ea9ed5e65, not stripped
```

### Protections:
```
gdb-peda$ checksec
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```

## TL;DR
Control of input string and pointer value leads to return-to-libc exploit.

## Analysis

### On the Case
Executable 'bf' takes a user input string and passes to a do_brainfuck() function for parsing. 

![do_brainfuck]({{site.url}}/objects/pwnableskr-brain-fuck/do_brainfuck.png "do_brainfuck")

The do_brainfuck() function has a case statement that recognizes six characters:

```
0x3e = > = eax + 1
0x3c = < = eax - 1
0x2b = + = *eax + 1
0x2d = - = *eax - 1
0x2e = . = putchar
0x2c = , = getchar

0x5b = [ = puts
```

### User's Fault
Knowing what characters are recognized we try to illicit a response from the program:

```
# ./bf
welcome to brainfuck testing system!!
type some brainfuck instructions except [ ]
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>........................
```

Eventually, we are able to segfault:
```
# ./bf
welcome to brainfuck testing system!!
type some brainfuck instructions except [ ]
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<.>.>.>.><<<<,>,>,>,><<<<>>>>>>>>>>>>>>>>,>,>,>,>


.
.
Segmentation fault
```

Furthermore, we are able to submit not just the valid parser characters, but can store anything, and access it:
```
# ./bf
welcome to brainfuck testing system!!
type some brainfuck instructions except [ ]
aaaa-------,.,.,.,.
bbbb-------,.,.,.,.
bbbb
```

Note that the final four b's were returned by bf to us.

The real progress is playing with the pointer reference:
```
# ./bf
welcome to brainfuck testing system!!
type some brainfuck instructions except [ ]
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<----------------------------.>.>
�
```

That was not an input character! We do not have a format string vulnerability, but we are getting bytes outside of input. Since NX bit is enabled, our input is not in an executable segment of memory. Considering that we control a pointer, can we somehow use getchar to read an address and use putchar to alter it?

### Arriving at libc
Since bf is a dynamically linked binary, and we are provided the libc linked library file, return-to-libc seems like the attack of choice. You are familiar with the Global Offset Table (GOT) and Procedure Linkage Table (PLT), right? If not, start with [System Overlord's introduction](https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html). 

```
# objdump -d bf | grep @plt
...
 80484fc:   e8 9f ff ff ff          call   80484a0 <__libc_start_main@plt>
 8048648:   e8 83 fe ff ff          call   80484d0 <putchar@plt>
 8048655:   e8 e6 fd ff ff          call   8048440 <getchar@plt>
 8048665:   e8 06 fe ff ff          call   8048470 <puts@plt>
 80486b4:   e8 f7 fd ff ff          call   80484b0 <setvbuf@plt>
 80486d9:   e8 d2 fd ff ff          call   80484b0 <setvbuf@plt>
 80486ef:   e8 7c fd ff ff          call   8048470 <puts@plt>
 80486fb:   e8 70 fd ff ff          call   8048470 <puts@plt>
 8048717:   e8 a4 fd ff ff          call   80484c0 <memset@plt>
 8048734:   e8 17 fd ff ff          call   8048450 <fgets@plt>
 804876b:   e8 20 fd ff ff          call   8048490 <strlen@plt>
 8048789:   e8 d2 fc ff ff          call   8048460 <__stack_chk_fail@plt>
```

The linked functions (with '@plt' references) contain jumps to the linked library file (in this case, the provided bf_libc.so).

To exploit return-to-libc, we will need to determine the base address and the offsets of our functions. The offsets we can glean from the libc file:

```
# readelf -s bf_libc.so | grep system
   245: 001108c0    68 FUNC    GLOBAL DEFAULT   13 svcerr_systemerr@@GLIBC_2.0
   627: 0003a920    55 FUNC    GLOBAL DEFAULT   13 __libc_system@@GLIBC_PRIVATE
  1457: 0003a920    55 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.0
```
The system() offset is 0x0003a920.

```
# readelf -s bf_libc.so | grep putchar@@
   504: 00060c80   294 FUNC    GLOBAL DEFAULT   13 putchar@@GLIBC_2.0
   ```

The putchar() offset is 0x00060c80. 

Now we just need a way to leak an address.



### Static Data is BSS
Within the bss (the data segment), there is *p (0x0804a080) which is presumably the pointer that we control, and immediately below that is tape (0x0804a0a0). Our input is stored at tape, and determined by instruction 0x080485f5: EAX*4+0x8048848. We are in bss with control of a string and a pointer to reference that string.

Since NX bit is enabled, we cannot write to the bss segment. Consequently, we need to find an executable segment of memory. Enter return-to-libc. This is facilitated by being able to control pointer *p and a lack of boundary checking. Since the program's behavior allows us to read and write values, we should be able to access libc functions by reference.

![bf layout]({{ site.url }}/objects/pwnableskr-brain-fuck/bf-layout.png "bf layout")

Since we know the address of tape within the bss, and we know the .got.plt addresses, we can move from the bss into the .got.plt and use our brainfuck syntax to output the address. From there, we can calculate the libc base address and jump to other funcitons.

Our attack is coming together; we will use return-to-libc to overwrite GOT addresses and build out a system() call to execute a shell.

### PLT Address Lookup

To manually determine the PLT address, we can use objdump:

1. Find the local address being called
2. Find references to the called address
3. Identify linked address we jump to

```
# objdump -d bf | grep fgets
08048450 <fgets@plt>:
 8048734:   e8 17 fd ff ff          call   8048450 <fgets@plt>
# objdump -d bf | grep 8048450
08048450 <fgets@plt>:
 8048450:   ff 25 10 a0 04 08       jmp    *0x804a010
 8048734:   e8 17 fd ff ff          call   8048450 <fgets@plt>
```

## Exploit
We can leak a libc function address. Since we have the libc binary, we can calculate the libc base address and jump to any inclued function. Since we are able to move into the plt.got table and modify function addresses, we control what functions we execute.

1. Determine current address within bss
2. Move into GOT address space. 
3. Leak GOT address
4. Calculate base libc address
5. Setup system() call
6. Return to function that will execute linked function
7. Get shell
8. Upload cats to the internet

## References
[Return-to-libc attack](https://en.wikipedia.org/wiki/Return-to-libc_attack)

[Bypassing NX bit using return-to-libc](https://sploitfun.wordpress.com/2015/05/08/bypassing-nx-bit-using-return-to-libc/ "sploitfun") - Understanding non-executable memory protection to prevent classic stack buffer overflows

[GOT and PLT for pwning.](https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html) - Introduction to Global Offset Table (GOT) and Procedure Linkage Table (PLT) attacks.

[how2exploit](https://github.com/bert88sta/how2exploit_binary) - Good introductory resource for [help with pwntools](https://github.com/bert88sta/how2exploit_binary/tree/master/exercise-4) and executing [system() return-to-libc](https://github.com/bert88sta/how2exploit_binary/tree/master/exercise-2)

