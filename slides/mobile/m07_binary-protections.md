## M07:2024 — Insufficient Binary Protections
**🟡 Medium** | CWE-656 · CWE-693

> Unprotected binaries can be reverse-engineered, tampered with,  
> or repackaged — extracting secrets and bypassing business logic.

--

## How It Works + Real-World Example

**Decompiling an APK exposes source:**

```bash
# Anyone can do this with a downloaded APK
jadx-gui myapp.apk
# → Readable Java/Kotlin source code
# → Business logic, API endpoints, hardcoded values visible

# Repackaging with malicious code:
apktool d myapp.apk
# edit smali to add malware
apktool b myapp -o myapp-trojan.apk
jarsigner -keystore my.keystore myapp-trojan.apk alias
# → Identical-looking app with malware
```

Note: APK = Android Package. jadx = Java decompiler that produces readable Java/Kotlin from Android bytecode. apktool = disassembles APKs to Smali. Smali = assembly language of Android's Dalvik/ART bytecode. Repackaging = modifying a decompiled APK and signing it with a new key — results in an identical-looking app.

**Real-world**: WhatsApp "Gold" (recurring) — repackaged WhatsApp APKs distributed outside Play Store contain spyware.

Note: R8 = the code shrinker and obfuscator built into Android Gradle — renames classes and methods to single letters, making decompiled code much harder to read (though not impossible). Google Play Integrity API = server-side attestation that a request is coming from an unmodified app running on a genuine Android device — replaces the deprecated SafetyNet API. The original app's code is extracted and modified; millions of users install trojanized versions.

--

## Mitigation & References

```gradle
// Android — enable R8 obfuscation + shrinking
android {
    buildTypes {
        release {
            minifyEnabled true       // enable code shrinking
            shrinkResources true     // remove unused resources
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'),
                         'proguard-rules.pro'
        }
    }
}
```

```kotlin
// Runtime integrity check (detect tampering)
val packageInfo = packageManager.getPackageInfo(packageName,
    PackageManager.GET_SIGNATURES)
val sig = packageInfo.signatures[0].toCharsString()
check(sig == EXPECTED_SIGNATURE) { "App integrity check failed" }
```

| Resource | Details |
|---|---|
| R8 / ProGuard | Android code obfuscation |
| SwiftShield | iOS symbol obfuscation |
| [Google Play Integrity API](https://developer.android.com/google/play/integrity) | Runtime attestation |
| Apple App Attest | iOS attestation |
