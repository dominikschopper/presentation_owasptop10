## A04:2025 — Cryptographic Failures
CWE-261 / CWE-296 / CWE-310 / CWE-319

> Weak or absent cryptography leading to exposure of sensitive data.
> Previously "Sensitive Data Exposure" — 2025 focuses on the **root cause**.

Note: Covers everything from storing passwords in plain text, using deprecated algorithms (MD5, SHA-1, DES), missing TLS, to subtle implementation errors like ECB mode or unauthenticated encryption.

--

## How It Works

**Weak password hashing:**
```python
# VULNERABLE — MD5 is not a password hash
import hashlib
stored = hashlib.md5(password.encode()).hexdigest()
# Cracked in seconds with rainbow tables
```

**Transmitting sensitive data over HTTP:**
```http
POST /login HTTP/1.1
Host: example.com          ← no TLS!
Content-Type: application/x-www-form-urlencoded

username=alice&password=s3cr3t   ← visible to any network observer
```

**ECB mode — patterns leak through encryption:**
```python
# VULNERABLE — AES-ECB
cipher = AES.new(key, AES.MODE_ECB)
# Identical plaintext blocks → identical ciphertext blocks
# → attacker can see structure even without decrypting
```

Note: MD5/SHA-1 = cryptographic hash functions, fast by design — which makes them catastrophically bad for passwords (rainbow tables crack them in seconds). ECB = Electronic Codebook — AES mode that encrypts each 16-byte block independently, so identical plaintext blocks produce identical ciphertext. TLS = Transport Layer Security — the encryption protocol behind HTTPS.

--

## Real-World Examples

**Heartbleed — CVE-2014-0160**
- Buffer over-read in OpenSSL's heartbeat extension
- Attacker sends crafted heartbeat → server returns 64KB of heap memory
- **Impact**: private keys, session tokens, passwords from millions of servers

**RockYou Data Breach (2009)**
- 32M passwords stored in **plain text**
- Leaked file became the most-used wordlist for password attacks
- **Impact**: All 32M passwords immediately usable for credential stuffing

Note: OpenSSL is the most widely used TLS library. Heartbleed sent a heartbeat packet claiming to be larger than it was, causing the server to echo back 64KB of heap memory containing private keys, session tokens, and passwords — without leaving any log entry.

--

## Mitigation

1. Use **bcrypt/scrypt/Argon2** for passwords — never MD5/SHA-1
2. Enforce **TLS 1.2+** everywhere; disable older versions
3. Use **AES-256-GCM** (authenticated encryption) for data at rest

```javascript
// FIXED — bcrypt for password storage
const bcrypt = require('bcrypt');
const SALT_ROUNDS = 12;

async function hashPassword(plain) {
  return bcrypt.hash(plain, SALT_ROUNDS);
}
async function verify(plain, hash) {
  return bcrypt.compare(plain, hash);
}
```

```python
# FIXED — AES-GCM (authenticated encryption)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
key = AESGCM.generate_key(bit_length=256)
aead = AESGCM(key)
nonce = os.urandom(12)
ciphertext = aead.encrypt(nonce, plaintext, associated_data)
```

Note: GCM = Galois/Counter Mode — an authenticated encryption mode for AES that provides both confidentiality AND integrity (detects tampering). SALT_ROUNDS in bcrypt = the work factor — higher = slower = harder to brute-force. Argon2 won the Password Hashing Competition (2015) and is the current recommendation.

--

## References & Tools

| Resource | Details |
|---|---|
| [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) | Algorithm guidance |
| [OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) | bcrypt/Argon2 guidance |
| SonarQube | Detects weak algorithms, hardcoded keys |
| `testssl.sh` | Server TLS configuration auditing — checks cipher suites, protocol versions |
| Snyk | Flags crypto-vulnerable package versions (e.g. old OpenSSL, weak JWT libraries) |

Note: NIST SP 800-131A defines which cryptographic algorithms are approved vs. disallowed. testssl.sh is a shell script that runs against any TLS endpoint and reports deprecated protocol versions (SSLv3, TLS 1.0/1.1), weak cipher suites, and certificate issues.
