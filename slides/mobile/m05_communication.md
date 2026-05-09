## M05:2024 — Insecure Communication
**🟠 High** | CWE-295 · CWE-319 · CWE-326

> Apps transmit sensitive data over insecure channels,  
> or disable TLS validation — enabling network interception.

--

## How It Works + Real-World Example

**Custom TrustManager — accepts any certificate:**

```java
// VULNERABLE — disabling TLS validation (common "fix" for development)
TrustManager[] trustAllCerts = new TrustManager[] {
    new X509TrustManager() {
        public void checkClientTrusted(X509Certificate[] c, String a) {}
        public void checkServerTrusted(X509Certificate[] c, String a) {}
        public X509Certificate[] getAcceptedIssuers() { return null; }
    }
};
SSLContext sc = SSLContext.getInstance("SSL");
sc.init(null, trustAllCerts, new SecureRandom());
// ↑ Accepts expired, self-signed, malicious certificates!
```

Note: TrustManager = the Java/Android interface responsible for deciding whether a TLS certificate is trusted. A custom TrustManager with empty checkServerTrusted() accepts any certificate — including expired, self-signed, or attacker-issued ones. This is a common developer shortcut for bypassing SSL errors in development that frequently ships to production. TLS = Transport Layer Security. MITM = Man-in-the-Middle.

**Real-world — Fahl et al. "Why Eve and Mallory Love Android" (IEEE S&P 2012)**: Academic study of 13,500 Android apps found ~1,000 accepting all certificates or hostnames. Named apps including banking and payment clients had custom TrustManagers effectively disabling TLS validation in production — making them vulnerable to any attacker on the same Wi-Fi network.

Note: Certificate pinning = embedding the expected server certificate or public key hash directly in the app, so it only trusts that specific certificate even if a CA-signed certificate is presented. mitmproxy and Charles Proxy are used during testing to intercept HTTPS traffic by installing a custom root CA — pinning prevents this.

--

## Mitigation & References

```xml
<!-- Android Network Security Config — certificate pinning -->
<!-- res/xml/network_security_config.xml -->
<network-security-config>
    <domain-config>
        <domain includeSubdomains="true">api.example.com</domain>
        <pin-set expiration="2025-12-31">
            <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
            <pin digest="SHA-256">BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

| Resource | Details |
|---|---|
| [OWASP Certificate Pinning](https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning) | Guide |
| TrustKit (iOS/Android) | Certificate pinning library |
| mitmproxy / Charles Proxy | Test TLS interception |
