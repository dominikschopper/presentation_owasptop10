## API8:2023 — Security Misconfiguration
**🟡 Medium** | CWE-16 · CWE-388

> Same class as web misconfiguration, but API-specific:  
> permissive CORS, unnecessary HTTP methods, verbose errors, no TLS.

Note: APIs often skip hardening steps applied to web apps. CORS wildcard is especially common because developers add it during local development and forget to restrict it in production.

--

## How It Works

**CORS wildcard — any origin can call your API:**

```http
# API response:
Access-Control-Allow-Origin: *
# Any website can now make authenticated cross-origin requests
# → reads data, makes transactions on behalf of logged-in user
```

**Verbose error exposing internals:**
```json
HTTP/1.1 500 Internal Server Error
{
  "error": "FATAL ERROR",
  "exception": "org.postgresql.util.PSQLException",
  "detail": "ERROR: column \"admin_override\" of relation \"users\" does not exist",
  "sql": "INSERT INTO users (name, email, admin_override) VALUES (?, ?, ?)",
  "host": "prod-rds.eu-west-1.rds.amazonaws.com:5432"
}
```

**Unnecessary HTTP methods enabled:**
```bash
curl -X TRACE https://api.example.com/   → 200 OK (XST attack vector)
curl -X OPTIONS https://api.example.com/ → reveals full method list
```

Note: CORS = Cross-Origin Resource Sharing — the browser mechanism that controls which origins can make cross-domain requests. `*` means any website can read the API response. CORS only protects browser-based requests — an attacker can always call your API directly from a server, so CORS is not a security boundary by itself, but it prevents malicious websites from stealing data from authenticated browser sessions. XST = Cross-Site Tracing — HTTP TRACE reflects the request including cookies, enabling theft via XSS.

--

## Real-World Examples

**Facebook (2018) — CORS misconfiguration**
- `graph.facebook.com` had overly permissive CORS for internal tools
- Third-party sites could silently query user data via browser
- **Impact**: Privacy violation; patched after researcher disclosure

**Shopify (2019) — Verbose errors**
- Internal GraphQL errors exposed database schema, field names, and internal IDs
- Used to enumerate private API fields not in public documentation
- **Impact**: Schema information disclosure

Note: The Facebook CORS issue was reported via the Facebook bug bounty program. Shopify's GraphQL verbose errors exposed their internal data model — attackers could use this to identify fields to probe with mass assignment or BOPLA attacks, effectively turning error messages into API documentation.

--

## Mitigation

1. **Restrict CORS** to explicit allowed origins — never `*` for authenticated APIs
2. Return **generic errors** to clients; log details internally
3. Disable debug mode, unnecessary HTTP methods, and stack traces in production

```javascript
// FIXED — explicit CORS whitelist
const cors = require('cors');
const allowedOrigins = ['https://app.example.com', 'https://admin.example.com'];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
}));
```

--

## References & Tools

| Resource | Details |
|---|---|
| [OWASP CORS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/CORS_Cheat_Sheet.html) | CORS configuration guide |
| [SecurityHeaders.com](https://securityheaders.com) | Header scanner |
| 42Crunch | API security scanning |
| OWASP ZAP | Misconfiguration detection |
