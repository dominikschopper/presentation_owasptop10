## M06:2024 — Inadequate Privacy Controls
**🟠 High** | CWE-359 · CWE-200

> Apps collect, store, or transmit more personal data than necessary  
> without user consent, transparency, or proper data controls.

--

## How It Works + Real-World Example

**Excessive permission requesting:**

```xml
<!-- VULNERABLE — permissions unnecessary for core function -->
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
<uses-permission android:name="android.permission.READ_CALL_LOG"/>
<uses-permission android:name="android.permission.RECORD_AUDIO"/>
<!-- A flashlight app requesting all of these? -->
```

**Sending PII to analytics without consent:**
```javascript
// VULNERABLE — full user profile in analytics
analytics.track('page_view', {
  userId: user.id,
  email: user.email,       // ← PII
  phone: user.phone,       // ← PII
  location: gps.current(), // ← precise location
  deviceId: device.imei,   // ← persistent identifier
});
```

Note: PII = Personally Identifiable Information. IMEI = International Mobile Equipment Identity — a unique 15-digit hardware identifier for a mobile device; persistent across factory resets. GDPR = General Data Protection Regulation (EU, 2018) — requires lawful basis for collecting PII. CCPA = California Consumer Privacy Act (2020) — similar requirements for California residents.

**Real-world**: TikTok (2022) — US-based TikTok data including biometric identifiers was found to be transmitted to Chinese servers without adequate disclosure, triggering congressional hearings and ongoing litigation.

Note: Exodus Privacy (exodus-privacy.eu.org) is a non-profit that analyzes Android APKs and lists the tracking SDKs embedded in each app — a useful transparency tool for users and a red-flag list for developers evaluating which analytics SDKs to include.

--

## Mitigation & References

```kotlin
// Request permissions at runtime, only when needed
class CameraFragment : Fragment() {
    private fun openCamera() {
        when {
            ContextCompat.checkSelfPermission(requireContext(),
                Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED -> {
                startCamera()  // already granted
            }
            else -> requestPermissionLauncher.launch(Manifest.permission.CAMERA)
        }
    }
}
```

| Resource | Details |
|---|---|
| Android Privacy Dashboard | Audit app permission usage |
| [GDPR / CCPA guidelines](https://gdpr.eu/) | Consent requirements |
| iOS App Privacy Report | Track data access |
| [Exodus Privacy](https://exodus-privacy.eu.org) | Tracker detection in Android apps |
