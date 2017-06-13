from pwn import *

breakAddress = 0x004006dd       # Address with compare instruction
targetRegister = '$rdx'         # Value that we want to identify

breakCommand = '''set logging file russian.log
set logging on
break *{}
command 1
# Commenting silent out breaks output (print statements do not display)
silent
print {}
continue
end
'''.format(breakAddress, targetRegister)

# Characters to use for bruting flag
chars = [chr(x) for x in range(41, 126)]

flag = 'a'*32

p = process('./russia')

print('-'*80)
d = gdb.attach(
    p, 
    gdbscript=breakCommand, 
    exe='./russia') 

d.send('run '+flag+'\n')
d.recv(timeout=1.0)
d.close()

# This does nothing; hangs on 'waiting for debugger'
# even though ps shows process as defunct
#d.close()

