from pwn import *
from math import comb

p = remote("10.0.118.104",6464)

n = int(p.recvline().strip())
print("n =", n)

for i in range(n+1):
    p.sendline(str(comb(n,i)).encode())

p.interactive()