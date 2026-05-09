## M02:2024 — Inadequate Supply Chain Security
**🔴 Critical** | CWE-494 / CWE-829

> Malicious or vulnerable third-party SDKs, libraries,
> and build tools introduce risk into the app's supply chain.

--

## How It Works + Real-World Example

Mobile apps integrate dozens of SDKs (analytics, ads, crash reporting) — each is a trust boundary:

```gradle
// VULNERABLE — unpinned, unverified SDK versions
dependencies {
    implementation 'com.thirdparty:analytics-sdk:+'  // ← latest, unverified!
    implementation 'com.ads:sdk:2.3.+'               // ← wildcard — can update silently
}
```

Note: SDK = Software Development Kit — a pre-packaged library for easy integration of third-party functionality (analytics, ads, crash reporting, payments). Each SDK is a trust boundary: it runs with the same permissions as your app and has access to everything your app has access to. SCA = Software Composition Analysis — automated scanning of dependency lists against vulnerability databases.

**Real-world — Goldoson malware (2023)**
- Malicious library distributed via legitimate app stores

- Embedded in 60+ legitimate South Korean apps (200M+ installs)
- Collected location data, app lists, WiFi/Bluetooth info, performed ad fraud
- **Impact**: Active in production apps for months before detection

Note: Goldoson was a third-party library (not the apps themselves) that was included by developers without knowing it contained malware. It collected device app lists, nearby Wi-Fi/Bluetooth devices, and GPS location — and performed ad fraud by clicking ads in the background. Google Play SDK Index was created partly in response to incidents like this to help developers evaluate SDK safety before integrating.

--

## Mitigation & References

```gradle
// FIXED — pin exact versions and verify checksums
dependencies {
    implementation 'com.thirdparty:analytics-sdk:3.2.1'  // pinned
}

// verify module integrity in gradle:
configurations.all {
    resolutionStrategy {
        failOnVersionConflict()
        force 'com.thirdparty:analytics-sdk:3.2.1'
    }
}
```

| Resource | Details |
|---|---|
| Snyk for Mobile | SDK vulnerability scanning |
| [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/) | SCA for mobile |
| Google Play SDK Index | Vetting SDK safety |
| MobSF | Identifies risky SDK permissions |
