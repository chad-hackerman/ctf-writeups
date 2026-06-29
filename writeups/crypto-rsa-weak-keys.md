# Cryptography — RSA Weak Keys (Common Modulus Attack)

**Category:** Cryptography
**Difficulty:** Hard
**Tools Used:** Python, gmpy2
**Key Learning:** Importance of proper key generation and padding schemes

---

## Challenge Description

Two ciphertexts encrypted with RSA are provided. Both were encrypted using the same plaintext message but with different public keys. The public exponent `e` is small (e=3). Recover the plaintext.

**Given:**
```
n1 = 854325...  (2048-bit modulus)
e1 = 3
c1 = 219847...  (ciphertext 1)

n2 = 901234...  (2048-bit modulus)
e2 = 3
c3 = 674123...  (ciphertext 2)
```

---

## Background — Why This Attack Works

RSA encryption: `c = m^e mod n`

If the same message `m` is encrypted with the same small exponent `e` under two different moduli `n1` and `n2`, and `gcd(n1, n2) = 1`, the Chinese Remainder Theorem (CRT) lets us recover `m^e` over `n1 * n2`.

When `e=3` and the message is short enough that `m^3 < n1 * n2`, then `m^3` is just a perfect cube — no modular reduction occurred. Taking the integer cube root directly gives us `m`.

This is called **Håstad's Broadcast Attack**.

---

## Solution

### Step 1 — Verify gcd(n1, n2) = 1

```python
import gmpy2

# If gcd != 1, we could factor both moduli directly (even easier!)
g = gmpy2.gcd(n1, n2)
print(f"gcd(n1, n2) = {g}")
# Output: gcd(n1, n2) = 1  → proceed with CRT
```

### Step 2 — Apply Chinese Remainder Theorem

We want to find `x` such that:
```
x ≡ c1 (mod n1)
x ≡ c2 (mod n2)
```

Where `x = m^3` (since e=3 and same message was used).

```python
def extended_gcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x, y = extended_gcd(b, a % b)
    return g, y, x - (a // b) * y

def crt(r1, n1, r2, n2):
    """Chinese Remainder Theorem for two congruences."""
    _, m1, m2 = extended_gcd(n1, n2)
    N = n1 * n2
    x = (r1 * m2 * n2 + r2 * m1 * n1) % N
    return x

m_cubed = crt(c1, n1, c2, n2)
print(f"Recovered m^3 = {m_cubed}")
```

### Step 3 — Integer Cube Root

```python
# gmpy2's iroot returns (root, is_perfect_root)
m, is_perfect = gmpy2.iroot(m_cubed, 3)

if is_perfect:
    print(f"[+] Perfect cube root found!")
    # Convert integer back to bytes
    m_bytes = m.to_bytes((m.bit_length() + 7) // 8, byteorder='big')
    print(f"[+] Plaintext: {m_bytes.decode()}")
else:
    print("[-] Not a perfect cube — message may be padded or larger than n1*n2")
```

### Full Exploit Script

```python
import gmpy2

# Challenge values (truncated for readability)
n1 = int("854325...", 16)
e1 = 3
c1 = int("219847...", 16)

n2 = int("901234...", 16)
e2 = 3
c2 = int("674123...", 16)

def extended_gcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x, y = extended_gcd(b, a % b)
    return g, y, x - (a // b) * y

def crt(r1, n1, r2, n2):
    _, m1, m2 = extended_gcd(n1, n2)
    N = n1 * n2
    return (r1 * m2 * n2 + r2 * m1 * n1) % N

# Step 1: CRT to recover m^e
m_cubed = crt(c1, n1, c2, n2)

# Step 2: Integer cube root
m, perfect = gmpy2.iroot(m_cubed, 3)

if perfect:
    flag = m.to_bytes((m.bit_length() + 7) // 8, 'big').decode()
    print(f"[+] Flag: {flag}")
else:
    print("[-] Cube root not perfect — check inputs")
```

**Output:**
```
[+] Flag: CTF{h4st4ds_br04dc4st_att4ck_str1k3s_4g41n}
```

---

## Key Takeaways

- **Never reuse the same message** across multiple RSA public keys with a small exponent
- **Small public exponents (e=3)** are dangerous without proper padding (OAEP)
- **PKCS#1 v1.5 and OAEP padding** prevent this attack by randomizing the message before encryption
- The attack requires only `e` ciphertexts encrypted under different moduli — scales with larger `e` too

---

*[← Back to Writeups Index](../README.md)*
