---
layout: default
category: CTF
tags: [reversing, ctf]
---
# Circle City Con CTF (C4TF)
## Russia - Let's Compare Ourselves

Binary: [russia](https://ginjabenjamin.github.io/objects/2017-06-12-CircleCityCon-Russia/russia)
Solution: [auto-cmp.py](https://ginjabenjamin.github.io/objects/2017-06-12-CircleCityCon-Russia/auto-cmp.py)

## Challenge

### Type: 
Reverse Engineering

#### File: 
russia: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=f974aef4a26e61c61a5e4efa8b56669f1e01916c, stripped

#### Protections:
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial


## TL;DR
Break at 0x004006dd, examine RAX to brute the 32 flag characters (minus 'C4TF{...}').

## Analysis
If no arguments are passed, usage is output:
```
Usage: ./russia <flag>
```

Executable expects a flag argument to be passed. We see this at 0x00400606, which is looking for one commandline argument, or the program branches, shows usage and exits.

Early in main(), we also see a compare instruction after a strlen() call:

```
  400645:   bf e0 07 40 00          mov    edi,0x4007e0
  40064a:   e8 61 fe ff ff          call   4004b0 <strlen@plt>
  40064f:   48 39 c3                cmp    rbx,rax
```

Breaking at 0x0040064f we can determine that the condition we need to meet is 32. Sure enough, passing a flag of 32 characters, we get further into the program, arriving at the algorithm where the magic happens.

![Russian Algorithms](https://ginjabenjamin.github.io/objects/2017-06-12-CircleCityCon-Russia/russia.png "Russian Algorithms")

In the 0x00400690 block, we see some math/logic operations, and ultimately a compare operation (0x004006dd) against EAX and EDX. By stepping though, we determine that RAX (EAX for CMP) is the current character (as determined from the counter variable RDP-0x14) from our input string and RDX (EDX for CMP) is the current target flag character.

# In Soviet Russia, Flag Solves You
## Or, How I learned to Resent Pwntools and Automate the Comparison
This is a good example of a common reversing engineering challenge that is easier to  brute force than reverse the alogrithm. In the past, I had tried to automate these to make time for more complex challenges. I wanted a Pwntools script to:
1. Fire off GDB
2. Setup a breakpoint on CMP operation
3. Display the target/desired value

Unfortunately, pwn.gdb.attach() has some issues. Ther are a few writeups that appear to use it simplistically, but trying to grab the output was not working for me. I tried logging, STDOUT redirection, teeing... No luck. Attach does not appear to return the tube that it is supposed to; we cannot fully interact with it like a normal process. Furthermore, when your debugging process finishes, pwntools does not recognize that it ends and sits there waiting, leaving the reported process as defunct. The 'waiting for debugger' should only show when waiting on the process, but the process has already completed, with our desired output flashing by and not ending up in a log or output file. So it looks like pwntools may be waiting on the wrong process. Once a couple teammates told me that they had failed to get pwn.gdb.attach() working in the past, I pursued another solution.

I found a [HackYou CTF writeup](https://blog.w3challs.com/?post/2012/10/13/HackYou-CTF-Reverse100%2C-Reverse200%2C-Reverse300-Writeups) that included a pythonGDB script that does exactly what I was looking for. After adjusting the script to work for me, I then made a wrapper Python script to generate the the pythonGDB script(s) based on all register-based compare operations for a specified binary. Still a bit manual, but no matter what these require a bit of actual analysis. In any event, [auto-cmp.py](https://ginjabenjamin.github.io/objects/2017-06-12-CircleCityCon-Russia/auto-cmp.py) has some reusability. 

That said, I would really like to finish the pwntool approach. If anyone has a solution...
