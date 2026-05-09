## A06:2025 — Insecure Design
**🟠 High** | CWE-73 · CWE-183 · CWE-209

> Flaws in architecture and design — not coding bugs,  
> but **missing or ineffective security controls by design**.

Note: Unlike the other categories, this can't be fixed by a patch. It requires rethinking the system's design. Threat modeling is the key preventive practice.

--

## How It Works

**Missing rate limiting — enables credential stuffing:**
```
Attacker runs 10M username:password pairs from breached lists
→ Login endpoint accepts unlimited requests
→ 0.5% success rate = 50,000 compromised accounts
→ Automated at 10,000 req/sec → done in 17 minutes
```

**Price parameter accepted from client:**
```http
POST /checkout
{"items": [{"id": "laptop-pro", "price": 0.01}]}
# Server trusts client-supplied price instead of looking it up
```

**Insecure password reset — security question with guessable answers:**
```
What is your mother's maiden name?  → findable on social media
What city were you born in?         → LinkedIn profile
```

Note: Credential stuffing = automated attack replaying username/password pairs from previous data breaches, exploiting password reuse across sites. At scale, even a 0.1% success rate across millions of credentials yields thousands of compromised accounts.

--

## Real-World Examples

**Twitter (2020) — Admin tool with no approval workflow**
- Attackers social-engineered Twitter employees into using an internal admin tool
- The tool could reassign any account's email/phone with no secondary approval
- High-profile accounts (Obama, Biden, Musk, Apple) hijacked in minutes
- **Impact**: $100K+ Bitcoin scam; design flaw was no "four-eyes" check for privileged operations

**Instagram (2019) — Phone number enumeration**
- Password reset revealed whether a phone number was registered
- Enabled targeted harassment and account enumeration at scale
- **Impact**: Privacy violation for millions of users

Note: The "four-eyes principle" (German: Vier-Augen-Prinzip) requires two independent people to approve high-risk actions — standard in banking and now increasingly required for admin operations on large platforms.

--

## Mitigation

1. **Threat model** during design — identify abuse cases, not just use cases
2. **Rate-limit** all authentication and sensitive business flows
3. Look up prices, permissions, and roles **server-side** — never trust client

```python
# Rate limiting with Flask-Limiter
from flask_limiter import Limiter

limiter = Limiter(app, key_func=get_remote_address)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")  # 5 attempts per minute per IP
def login():
    ...
```

```javascript
// Server-side price lookup — never trust client
async function checkout(cartItems) {
  const prices = await Promise.all(
    cartItems.map(item => db.getPrice(item.id))  // always from DB
  );
  return prices.reduce((sum, p) => sum + p, 0);
}

Note: STRIDE = Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege — Microsoft's threat modeling framework. PASTA = Process for Attack Simulation and Threat Analysis — a risk-centric methodology. ASVS = Application Security Verification Standard — OWASP's security requirements baseline with three levels of rigor.
```

--

## References & Tools

| Resource | Details |
|---|---|
| [OWASP Secure Product Design Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html) | Design principles |
| [OWASP Threat Modeling](https://owasp.org/www-community/Threat_Modeling) | STRIDE, PASTA |
| [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) | Security requirements baseline |
| express-rate-limit | Node.js rate limiting middleware |
| AWS WAF / Cloudflare | Edge-level rate limiting and bot protection |
