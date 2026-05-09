## API1:2023 — Broken Object Level Authorization
**🔴 Critical** | CWE-284 · CWE-639

> APIs fail to verify that the caller **owns** the object they're requesting.  
> Attackers enumerate IDs to access other users' resources.

Note: BOLA = IDOR at the API level. Most prevalent API vulnerability — responsible for ~40% of all API attacks. The difference from web IDOR: API responses often return structured data (JSON) that's immediately exploitable.

--

## How It Works

```http
# Attacker authenticates as user 42, then probes other users:
GET /api/v1/accounts/42/transactions  Authorization: Bearer <attacker_token>
→ 200 OK  { "balance": 1240.00, ... }   ← own account

GET /api/v1/accounts/43/transactions  Authorization: Bearer <attacker_token>
→ 200 OK  { "balance": 89432.00, ... }  ← victim's account (!)
GET /api/v1/accounts/44/transactions  → 200 OK ...
```

The server validates **authentication** (token is valid) but not **authorization** (does user 42 own account 43?).

```python
# VULNERABLE — no ownership check
@app.get('/api/accounts/{account_id}/transactions')
def get_transactions(account_id: int, user=Depends(get_current_user)):
    return db.query(Transaction).filter_by(account_id=account_id).all()
    # ↑ Never checks if account_id belongs to `user`
```

Note: BOLA = Broken Object Level Authorization — the API equivalent of IDOR (Insecure Direct Object Reference). Authentication = verifying who you are (valid token). Authorization = verifying what you're allowed to do (do you own this resource?). These are separate checks and both must be present.

--

## Real-World Examples

**Uber (2016) — Full platform BOLA**
- BOLA across rider and driver APIs
- Could access any user's trip history, profile, location, and payment methods
- **Impact**: potential account takeover for all ~40M users at the time

**Parler (2021)**
- Posts had sequential numeric IDs with no auth on the media endpoint
- Researchers downloaded all posts, videos, and GPS metadata (including "deleted" content)
- **Impact**: 80TB of data archived; used as evidence in legal proceedings

Note: The Uber 2016 BOLA was reported via HackerOne bug bounty — the researcher demonstrated accessing any user's account data by substituting their own user ID with other IDs in API calls. Parler's 2021 downfall: after AWS deplatformed them (January 2021), researchers bulk-downloaded all content before shutdown using the sequential ID vulnerability — the data later appeared in court proceedings related to January 6th.

--

## Mitigation

1. **Check ownership** on every object access — don't rely on the URL alone
2. Use **UUIDs** instead of sequential IDs (reduces enumeration — but not a substitute for auth)
3. Use a **policy engine** (OPA, Casbin) for consistent authorization

```python
# FIXED — always verify ownership
@app.get('/api/accounts/{account_id}/transactions')
def get_transactions(account_id: int, user=Depends(get_current_user)):
    account = db.get(Account, account_id)
    if not account or account.owner_id != user.id:
        raise HTTPException(status_code=403)   # explicit deny
    return account.transactions
```

Note: UUID = Universally Unique Identifier — harder to enumerate than sequential integers, but not a substitute for authorization. OPA = Open Policy Agent — a CNCF policy engine that evaluates authorization rules as code. Casbin = open-source authorization library supporting RBAC, ABAC, and ACL models.

--

## References & Tools

| Resource | Details |
|---|---|
| [OWASP BOLA Guide](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/) | Official guidance |
| [OWASP IDOR Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html) | Prevention patterns |
| 42Crunch | API security testing — scans for BOLA |
| Salt Security | Runtime BOLA detection in API traffic |
| Postman / Burp Suite | Manual BOLA testing |
