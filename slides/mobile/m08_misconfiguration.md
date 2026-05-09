## M08:2024 — Security Misconfiguration
**🟡 Medium** | CWE-16 · CWE-922

> Insecure build settings, overly permissive configurations,  
> and debug features left enabled in production builds.

--

## How It Works + Real-World Example

**`android:debuggable="true"` in production:**

```xml
<!-- VULNERABLE — debuggable in prod manifest -->
<application
    android:debuggable="true"   <!-- ← allows adb attach, code injection -->
    android:allowBackup="true"  <!-- ← allows adb backup of all app data -->
    ...>
```

```bash
# With debuggable=true, attacker can:
adb shell run-as com.example.myapp
# → full access to app's private files as the app's user
adb backup com.example.myapp
# → downloads all SharedPreferences, databases, files
```

Note: ADB = Android Debug Bridge — a command-line tool for communicating with Android devices over USB or TCP. `run-as` allows executing commands as the app's user ID, accessing its private data directory. android:allowBackup="true" allows `adb backup` to extract all SharedPreferences, databases, and files without root.

**Real-world**: Banking apps with `android:debuggable=true` discovered in Google Play Store (2021 study) — allowed ADB shell access to extract tokens and session data without rooting the device.

Note: MASTG = Mobile Application Security Testing Guide — OWASP's comprehensive testing guide, formerly MSTG. It covers every M01–M10 category with specific test cases. MobSF = Mobile Security Framework — an automated static and dynamic analysis tool that checks manifests, detects hardcoded secrets, and reports misconfigurations. `aapt` = Android Asset Packaging Tool — inspect APK manifests without decompiling.

--

## Mitigation & References

```xml
<!-- FIXED — secure manifest for release builds -->
<application
    android:debuggable="false"   <!-- set explicitly, don't rely on default -->
    android:allowBackup="false"  <!-- disable ADB backup -->
    android:networkSecurityConfig="@xml/network_security_config"
    ...>
```

```gradle
// Verify no debug config reaches release
android {
    buildTypes {
        release {
            debuggable false   // explicit override
            buildConfigField("boolean", "ENABLE_LOGGING", "false")
        }
    }
}
```

| Resource | Details |
|---|---|
| [OWASP MASTG](https://mas.owasp.org/MASTG/) | Mobile security testing guide |
| MobSF | Automated misconfiguration detection |
| `aapt dump badging` | Check APK manifest settings |
