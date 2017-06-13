'''
Generates scripts to be executed with gdb that break on CMP instructions
and set compared values equal to each other so that flags can be bruteforced

Resulting try*.py files need to be executed against binary using:
    # gdb [binary] -x try[address].py
    gdb$ run

    -or-

    # gdb [binary]
    gdb$ source try[address].py
    gdb$ run
'''
import os
import re
import subprocess
import sys

if(len(sys.argv) < 2):
    print('Usage: %s [binary]' % sys.argv[0])
    exit()
else:
    binary = sys.argv[1]

    if(binary[0] != '.' and binary[0] != '/'):
        binary = './' + binary

print('Targeting: {}'.format(binary))

script = '''flag = ""
 
def changeInputChar():
    global flag
 
    gdb.execute("set ${}=${}")
 
    flag += chr(gdb.parse_and_eval("$eax"))
 
    print("[+]", flag)

class HitBreakpoint(gdb.Breakpoint):
    def __init__(self, loc, callback):
        super(HitBreakpoint, self).__init__(
            loc, gdb.BP_BREAKPOINT, internal=False
        )
        self.callback = callback
 
    def stop(self):
        self.callback()
 
        return False
 
HitBreakpoint("*0x{}", changeInputChar)'''

# Find references to CMP and limit to those that are comparing two registers.
# Use the address for breakpoints, and use the compared registers in a set
# operation to brute force the 'flag'
cmd = "objdump --no-show-raw-insn -M intel -d " + binary
cmd += " | grep -e '[[:alnum:]]*:.*cmp\s*[er]\w\w,[er]\w\w'"

# Sed doesn't play nice and encode() didn't fix it
# cmd += " | sed 's/^[[:blank:]]*\([[:alnum:]]*\):\s*cmp\s*\(\w\w\w\),\(\w\w\w\)/"
# cmd += "\1,\3,\2/'"

p = subprocess.Popen([cmd], stdout=subprocess.PIPE, shell=True)
cmp = p.stdout.read()

# Because sed sucks...
cmp = re.sub(r':\s+cmp\s+', ',', cmp)

# Generate a script for each CMP
for l in cmp.split('\n'):
    # Break instruction into list {address, target, input}
    i = l.lstrip().split(',')

    if(len(i[0])):
        print('[+] Writing: try' + i[0] + '.py')
        f = open('try' + i[0] + '.py', 'w')
        f.write(script.format(i[2], i[1], i[0]))
        f.close
