## M01:2024 — Improper Credential Usage
**🔴 Critical** | CWE-522 · CWE-798

> API keys, passwords, and tokens hardcoded in app binaries  
> or stored in insecure locations — extractable by anyone with the APK.

--

## How It Works + Real-World Example

```java
// VULNERABLE — hardcoded in Android source
public class ApiClient {
    private static final String API_KEY = "sk_live_abc123...";  // in APK!
    private static final String DB_URL  = "postgres://admin:pass@db.internal";
}
```

**Extraction is trivial:**

```bash
# Anyone can decompile the APK
apktool d myapp.apk
grep -r "sk_live\|api_key\|password\|secret" ./smali/
```

Note: APK = Android Package — the installable format for Android apps. Anyone can download an APK from the Play Store and decompile it using jadx or apktool. Smali = the human-readable form of Android's Dalvik bytecode — strings, including API keys, appear in plain text in smali files.

**Real-world**: Researchers routinely find AWS keys, Firebase credentials, and payment keys in top-100 App Store apps. One 2023 study found valid cloud credentials in 14% of analyzed apps.

--

## Mitigation & References

**Fix**: Never embed credentials — load at runtime from a remote config or secure backend.

```kotlin
// FIXED — credentials fetched from backend, never in APK
class ApiClient {
    private val apiKey: String by lazy {
        // fetched on first authenticated call, stored in Keystore
        keystoreManager.getApiKey() ?: fetchFromBackend()
    }
}
```

Note: Android Keystore = a hardware-backed key storage system that performs cryptographic operations inside a dedicated security chip (TEE = Trusted Execution Environment or Secure Enclave on newer devices). Raw key material never leaves the hardware — even a compromised OS cannot extract it. The 2023 study referenced is "Secrets in Source Code" (Zahan et al.) which analyzed 5,000 top Play Store apps.

| Resource | Details |
|---|---|
| Android Keystore | Platform-provided secure credential storage |
| iOS Keychain | Platform-provided secure credential storage |
| [GitLeaks](https://github.com/gitleaks/gitleaks) | Pre-commit secret scanning |
| MobSF | Mobile Security Framework — static analysis |
