## A07:2025 — Identification & Authentication Failures
CWE-287 / CWE-295 / CWE-384

> Weak or broken authentication and session management.
> Allows attackers to assume other users' identities.

Note: Previously called "Broken Authentication" (2017). Expanded in 2021/2025 to include identification failures. Includes credential stuffing, session fixation, weak MFA, and insecure session management.

--

## How It Works

**Session fixation — token not rotated after login:**
```
1. Attacker gets a pre-auth session token: sessionid=abc123
2. Attacker tricks victim into using that token (link, cookie injection)
3. Victim logs in — server doesn't issue new token
4. Both attacker and victim share sessionid=abc123
5. Attacker is now authenticated as victim
```

**No account lockout — enables brute force:**
```python
# VULNERABLE — unlimited attempts
@app.route('/login', methods=['POST'])
def login():
    user = db.find_user(request.form['username'])
    if user and user.password == request.form['password']:
        session['user_id'] = user.id
        return redirect('/')
    return 'Invalid credentials', 401
# Attacker can try millions of passwords
```

Note: Session fixation = attacker pre-sets a session token, tricks the victim into authenticating with it, and then uses the now-authenticated token themselves. MFA = Multi-Factor Authentication — requiring something you know (password) + something you have (phone/token) or are (biometric).

--

## Real-World Examples

**Dropbox (2012, disclosed 2016)**
- Weak hashing (SHA-1 without salt) + 68M credentials from breach
- Passwords cracked and used for credential stuffing
- **Impact**: 68M accounts; prompted industry shift to bcrypt

**Uber (2016)**
- No rate limiting on phone-number-based auth
- Attacker enumerated valid accounts, intercepted SMS codes
- **Impact**: Full account takeover capability across all user tiers

Note: Salt = a random value added to each password before hashing, preventing rainbow table attacks and ensuring identical passwords produce different hashes. Dropbox migrated to bcrypt after the breach. The Uber (2016) SMS code interception refers to an SS7 (Signaling System No. 7) attack vector — the telecom protocol has known weaknesses that allow interception of SMS messages.

--

## Mitigation

1. **Rotate session tokens** on every login (invalidate pre-auth token)
2. Implement **MFA** — prefer TOTP/passkeys over SMS
3. Use **established auth frameworks** — don't roll your own

```javascript
// FIXED — regenerate session after login (express-session)
app.post('/login', async (req, res) => {
  const user = await authenticate(req.body);
  if (!user) return res.status(401).send('Invalid');

  req.session.regenerate((err) => {   // ← new session ID
    req.session.userId = user.id;
    res.redirect('/dashboard');
  });
});
```

```javascript
// TOTP verification with speakeasy
const speakeasy = require('speakeasy');
const valid = speakeasy.totp.verify({
  secret: user.totpSecret,
  encoding: 'base32',
  token: req.body.totpCode,
  window: 1,  // 30-second window
});
```

Note: TOTP = Time-based One-Time Password (RFC 6238) — the standard behind authenticator apps (Google Authenticator, Authy). Generates a 6-digit code every 30 seconds using a shared secret and the current time. Passkeys = FIDO2/WebAuthn credentials — phishing-resistant, device-bound, replacing passwords entirely. JWT = JSON Web Token — a signed token encoding user identity claims.

--

## References & Tools

| Resource | Details |
|---|---|
| [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) | Complete guide |
| [OWASP Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) | Token handling |
| Passport.js / Auth0 / Keycloak | Proven auth libraries |
| [Have I Been Pwned](https://haveibeenpwned.com/Passwords) | Check passwords against breach lists |
| SonarQube | Detects hardcoded credentials, weak session |
