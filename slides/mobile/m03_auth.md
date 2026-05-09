## M03:2024 — Insecure Authentication / Authorization
**🟠 High** | CWE-287 · CWE-285

> Authentication performed client-side or skipped on backend;  
> authorization not enforced per-request on the server.

--

## How It Works + Real-World Example

```java
// VULNERABLE — auth decision made client-side
if (localPrefs.getBoolean("isLoggedIn", false)) {
    showDashboard();   // ← check is only local!
}
// Attacker uses Frida to hook this method, always returns true
```

**Token not invalidated on logout:**
```
1. User logs in → receives JWT, valid 7 days
2. User logs out → app deletes token locally
3. Attacker had captured the token → still valid for 7 days
4. Backend never invalidates it
```

**Real-world**: Strava (2018) — Global heatmap exposed military base layouts because fitness tracking auth was opt-out and defaulted to public; server-side defaulted to sharing even when app showed private.

Note: Frida = a dynamic instrumentation toolkit that injects JavaScript into native processes at runtime, allowing testers to hook functions, bypass checks, and modify behavior without recompiling. Widely used by mobile penetration testers and attackers alike. JWT = JSON Web Token. jti = JWT ID claim — a unique identifier for each token, stored server-side to enable token revocation. Without it, there's no way to invalidate a JWT before its expiry. The Strava incident was particularly sensitive because it revealed patrol routes, secret facility locations, and troop numbers in active conflict zones.

--

## Mitigation & References

```kotlin
// FIXED — always verify auth server-side, short-lived tokens
// Backend JWT config:
val token = Jwts.builder()
    .setSubject(userId)
    .setExpiration(Date(System.currentTimeMillis() + 15 * 60 * 1000))  // 15 min
    .signWith(secretKey, SignatureAlgorithm.HS256)
    .compact()

// Backend: maintain token revocation list
// On logout: add token jti to Redis blocklist
```

| Resource | Details |
|---|---|
| [OWASP Mobile Auth](https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/) | MASTG auth tests |
| Frida | Dynamic instrumentation — test client-side auth |
| Firebase Auth / Auth0 | Proven mobile auth SDK |
