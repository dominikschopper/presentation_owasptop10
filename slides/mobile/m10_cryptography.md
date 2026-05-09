## M10:2024 — Insufficient Cryptography
**🟡 Medium** | CWE-327 / CWE-780 / CWE-326

> Weak algorithms, short keys, improper modes, or hardcoded keys
> in the app's cryptographic implementation.

--

## How It Works + Real-World Example

**ECB mode — patterns survive encryption:**

```java
// VULNERABLE — AES-ECB leaks structure
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
cipher.init(Cipher.ENCRYPT_MODE, secretKey);
byte[] encrypted = cipher.doFinal(data);
// ECB encrypts each 16-byte block independently
// → identical plaintext blocks → identical ciphertext blocks
// → attacker can see patterns even without the key
```

**Hardcoded encryption key:**
```java
// VULNERABLE — key is visible to anyone who decompiles the APK
private static final byte[] KEY = "my-secret-key-16".getBytes();
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEY, "AES"));
```

Note: ECB = Electronic Codebook — AES mode that encrypts each 16-byte block independently, causing identical plaintext blocks to produce identical ciphertext. This makes patterns visible even without the key (the "ECB penguin" demonstration shows this clearly). IV = Initialization Vector — a random value mixed with the key for the first block in CBC mode to prevent pattern leakage.

**Real-world**: Adobe (2013) — encrypted passwords with ECB-mode 3DES; identical passwords produced identical ciphertext, allowing statistical analysis of 153M user passwords.

Note: The Adobe breach was particularly bad because the password hints were stored in plain text alongside the encrypted passwords — users with the hint "my email password" and the same ciphertext as millions of others made mass cracking trivial. GCM = Galois/Counter Mode — authenticated encryption that detects tampering. Hardware-backed Keystore = keys stored in a TEE (Trusted Execution Environment) or Secure Enclave, never accessible to the OS or apps.

--

## Mitigation & References

```kotlin
// FIXED — AES-GCM with Android Keystore-generated key
val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
keyGenerator.init(
    KeyGenParameterSpec.Builder("my_key_alias",
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)          // GCM, not ECB
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setKeySize(256)
        .build()
)
val secretKey = keyGenerator.generateKey()  // stored in hardware-backed Keystore
```

| Resource | Details |
|---|---|
| Android Keystore | Hardware-backed key storage & crypto |
| iOS CryptoKit | Modern Swift cryptography |
| [OWASP Crypto Mobile](https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/) | Testing guide |
| MobSF | Detects weak crypto algorithms in APK |
