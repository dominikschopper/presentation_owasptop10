## API2:2023 — Broken Authentication
**🔴 Critical** | CWE-287 / CWE-307 / CWE-798

> Weak or missing authentication mechanisms specific to APIs.
> Includes exposed credentials, missing rate limits, and absent MFA.

Note: Different from web broken auth — APIs often have additional vectors: hardcoded API keys, leaked tokens in git, weak JWT implementations, and no lockout on token endpoints.

--

## How It Works

**Hardcoded API key in source code:**

```python
# VULNERABLE — committed to git
STRIPE_SECRET_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
OPENAI_API_KEY    = "sk-proj-abc123..."
AWS_SECRET        = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY..."
```

**Weak JWT — `alg: none` attack:**
```python
# VULNERABLE — accepts unsigned tokens
import jwt
token = jwt.decode(
    token,
    options={"verify_signature": False}  # ← never do this!
)
```

**No brute-force protection on auth endpoint:**
```bash
# Attacker runs credential stuffing with no limit
for i in $(seq 1 1000000); do
  curl -X POST /api/auth/login -d "user=alice&pass=$(dict $i)"
done
```

Note: JWT = JSON Web Token — a signed JSON payload used as an auth token. The `alg:none` attack exploits JWT libraries that honour a header field declaring the algorithm, allowing an attacker to strip the signature entirely. MFA = Multi-Factor Authentication. IMSI = International Mobile Subscriber Identity — a unique identifier tied to a SIM card.

--

## Real-World Examples

**Twitch (2021)**
- Server misconfiguration exposed internal infrastructure; credentials accessible
- Attackers accessed Twitch's entire codebase and 3 years of payout data
- **Impact**: 125GB data breach, $9.8B in streamer payouts exposed

**T-Mobile (2021)**
- API with no rate limiting on IMSI lookup
- Attacker enumerated 50M+ customer records via sequential queries
- **Impact**: SSN, names, addresses, phone numbers exposed

Note: The Twitch breach (October 2021) was posted on 4chan as "part one." The exact entry vector was not publicly confirmed by Twitch but involved a server configuration error. AWS credential exposure in git history is a separate well-documented pattern — GitGuardian reports detecting hundreds of thousands of such secrets in public repos annually. T-Mobile's 2021 IMSI API breach was discovered by a threat actor who sold the data before T-Mobile was notified.

--

## Mitigation

1. **Never hardcode secrets** — use environment variables + secrets vault
2. Enforce **rate limiting** and lockout on all auth endpoints
3. Use **short-lived tokens** (JWT exp ≤ 15 min) + refresh token rotation

```bash
# Detect secrets before they're committed
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
```

```javascript
// JWT with proper algorithm pinning and short expiry
const token = jwt.sign(
  { userId: user.id },
  process.env.JWT_SECRET,
  {
    algorithm: 'HS256',   // explicitly pin algorithm
    expiresIn: '15m',     // short-lived
  }
);
```

Note: Short-lived access tokens (e.g. 15-minute JWTs) paired with refresh token rotation: the refresh token is single-use and rotated on each use, limiting the window of exposure if a token is stolen. GitLeaks runs as a pre-commit hook and blocks commits containing patterns matching API keys, passwords, and tokens.

--

## References & Tools

| Resource | Details |
|---|---|
| [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) | Full guide |
| [GitLeaks](https://github.com/gitleaks/gitleaks) | Pre-commit secret scanning |
| GitGuardian / TruffleHog | CI/CD secret detection |
| HashiCorp Vault / AWS Secrets Manager | Runtime secrets management |
| Snyk | Detects exposed credentials in code |
