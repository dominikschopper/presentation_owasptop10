## M09:2024 — Insecure Data Storage
**🟡 Medium** | CWE-312 / CWE-922

> Sensitive data stored unencrypted on device — accessible
> to other apps, ADB backup, or physical device access.

--

## How It Works + Real-World Example

**Credentials in SharedPreferences (plain text):**

```java
// VULNERABLE — unencrypted SharedPreferences
SharedPreferences prefs = getSharedPreferences("config", MODE_PRIVATE);
prefs.edit()
    .putString("auth_token", token)    // ← readable by root/ADB
    .putString("user_password", pass)  // ← never store passwords!
    .apply();

// Attacker with ADB access:
// adb shell run-as com.example.app cat /data/data/com.example.app/shared_prefs/config.xml
// → all preferences in plain text
```

Note: SharedPreferences = Android's key-value storage, persisted as plain XML files in the app's data directory. ADB = Android Debug Bridge. On a rooted device or with debuggable=true, these files are trivially readable. SQLite databases are also stored unencrypted by default — sqlite3 opens them directly.

**Sensitive data in SQLite without encryption:**
```
/data/data/com.example.bank/databases/app.db
→ open with sqlite3 → all transactions, card numbers, session tokens visible
```

**Real-world**: Starbucks app (2014) — credentials stored in plain text in logs; researchers extracted usernames, passwords, and geolocation data from the device log.

Note: The Starbucks vulnerability was discovered by researcher Daniel Wood and disclosed via Starbucks' responsible disclosure process. EncryptedSharedPreferences (Jetpack Security) wraps SharedPreferences with AES-256-SIV for keys and AES-256-GCM for values — the master key is stored in the Android Keystore. SQLCipher is an open-source extension to SQLite that adds 256-bit AES encryption to the entire database file.

--

## Mitigation & References

```kotlin
// FIXED — EncryptedSharedPreferences (Jetpack Security)
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

val sharedPreferences = EncryptedSharedPreferences.create(
    context,
    "secret_prefs",
    masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)
```

| Resource | Details |
|---|---|
| EncryptedSharedPreferences | AndroidX encrypted preferences |
| SQLCipher | Encrypted SQLite for Android/iOS |
| iOS Data Protection | File-level encryption tied to passcode |
| [OWASP MASTG Data Storage](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/) | Testing guide |
