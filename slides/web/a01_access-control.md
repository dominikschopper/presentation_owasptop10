## A01:2025 — Broken Access Control
**🔴 Critical** | CWE-284 · CWE-285 · CWE-639

> Users act outside their intended permissions.  
> Found in **100%** of tested applications. #1 since 2021.

Note: Also absorbs SSRF in the 2025 edition. Covers IDOR, privilege escalation, horizontal/vertical access violations, and path traversal to restricted files.

--

## How It Works

**Insecure Direct Object Reference (IDOR)** — user controls an ID that maps to a resource they don't own:

```http
GET /api/invoices/1042    → attacker's invoice  ✓
GET /api/invoices/1043    → victim's invoice    ✓  ← no check!
```

**Missing function-level authorization** — restricted endpoints are hidden in the UI but not protected on the server:

```javascript
// VULNERABLE — only hides the button, doesn't enforce server-side
app.delete('/admin/users/:id', (req, res) => {
  // no role check!
  db.deleteUser(req.params.id);
});
```

Note: IDOR = Insecure Direct Object Reference — the user supplies an identifier (order ID, account number) that directly references a server-side object, and the server doesn't verify ownership. SSRF = Server-Side Request Forgery — server fetches a URL controlled by the attacker; absorbed into A01 in the 2025 edition.

--

## Real-World Examples

**Optus Data Breach (2022)**
- Unauthenticated API endpoint returned customer PII for any sequential customer ID
- **Impact**: ~10 million Australians' data exposed (names, DOB, passport/licence numbers)

**MOVEit Transfer — CVE-2023-34362**
- SQL injection + missing auth on file-transfer endpoints
- Cl0p ransomware group used it to exfiltrate data from 2,000+ organizations, 62M+ individuals
- Victims: British Airways, BBC, Zellis, US govt agencies

--

## Mitigation

1. **Deny by default** — explicitly grant access, never assume
2. Enforce **server-side authorization** on every request (never rely on client-side)
3. Use **unpredictable identifiers** (UUIDs) and validate ownership before returning data
4. Log authorization failures; alert on spikes

```javascript
// FIXED — check ownership before returning
app.get('/api/invoices/:id', requireAuth, async (req, res) => {
  const invoice = await db.getInvoice(req.params.id);
  if (!invoice || invoice.userId !== req.user.id) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  res.json(invoice);
});
```

Note: UUID = Universally Unique Identifier — a 128-bit random value that is not guessable or enumerable, unlike sequential integers. Reduces but does not eliminate IDOR risk; ownership verification is still required.

--

## References & Tools

| Resource | Details |
|---|---|
| [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) | Patterns: RBAC, ABAC, ReBAC |
| [OWASP IDOR Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html) | Concrete prevention steps |
| SonarQube | Taint-analysis rules for unvalidated ID flows reaching data access |
| Snyk Code | SAST — flags paths where user-controlled IDs reach DB queries without ownership checks |
| OWASP ZAP | Active scan for IDOR/authorization flaws |

Note: RBAC = Role-Based Access Control (user has a role that grants permissions). ABAC = Attribute-Based Access Control (decisions based on attributes of user, resource, environment). ReBAC = Relationship-Based Access Control (e.g. Google Zanzibar — "can user X access doc Y because they are in a group that owns it?").
