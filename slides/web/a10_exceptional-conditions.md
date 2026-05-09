## A10:2025 — Mishandling of Exceptional Conditions
CWE-390 / CWE-391 / CWE-703 / CWE-754

> Poor error handling, logical flaws, and insecure failure states
> expose sensitive data or enable DoS. **New in 2025.**

Note:
- information disclosure via stack traces,
- logic errors in error paths (e.g., auth bypass when exception occurs),
- resource exhaustion,
- fail-open vs fail-safe behavior.

--

## How It Works

**Stack trace in production response — information disclosure:**
```json
HTTP/1.1 500 Internal Server Error
{
  "error": "NullPointerException",
  "stack": "at com.example.UserController.getProfile(UserController.java:87)\n
            at com.example.auth.JwtFilter.doFilter(JwtFilter.java:52)\n
            SQL: SELECT * FROM sessions WHERE token='eyJhbGc...'",
  "dbHost": "prod-db.internal.example.com:5432"
}
```

**Fail-open authentication — exception bypasses auth:**
```python
# VULNERABLE — exception causes bypass
def require_auth(f):
    def wrapper(*args, **kwargs):
        try:
            token = validate_jwt(request.headers.get('Authorization'))
            g.user = token.user
        except Exception:
            pass  # ← exception swallowed → request proceeds unauthenticated!
        return f(*args, **kwargs)
```

Note:
- DoS = Denial of Service — making a system unavailable.
- OGNL = Object-Graph Navigation Language — an expression language embedded in Apache Struts that evaluates expressions at runtime.
- The fail-open pattern (exception → access granted) is a classic logic error in error handling paths.

--

## Real-World Examples

**Apache Struts — CVE-2017-5638 (Equifax)**
- Exception in file upload handling triggered OGNL expression evaluation
- Attacker injected arbitrary expressions in `Content-Type` header
- **Impact**: 147M records; the vulnerability was **error-handling logic**

**PHP Type Juggling (recurring)**
```php
// '0e...' strings == 0 in PHP loose comparison
if (md5($password) == $hash) { ... }
// md5('240610708') = '0e462097431906509019562988736854'
// == 0 == md5('QNKCDZO') → authentication bypass
```

Note:
- CVE-2017-5638 patched in Apache Struts in March 2017
- Equifax was breached in May 2017 (2 months after).
- root cause an error-handling design flaw
- AND not updating.

PHP type juggling is a design flaw in PHP's loose comparison operator (==) like in JS

--

## Mitigation

Note: Fail-closed = on error, deny access (safe default). Fail-open = on error, grant access (dangerous). The principle: security controls should default to restriction, not permission, when they encounter unexpected states.

1. **Never expose** stack traces, internal paths, or DB details to clients
2. **Fail closed** — on exception, deny access (not grant it)
3. Return **generic error messages** to users; log details server-side

```python
# FIXED — fail-safe auth decorator
def require_auth(f):
    def wrapper(*args, **kwargs):
        try:
            token = validate_jwt(request.headers.get('Authorization'))
            if not token:
                abort(401)
            g.user = token.user
        except Exception:
            abort(401)   # ← fail closed, never open
        return f(*args, **kwargs)
    return wrapper
```

```javascript
// FIXED — generic error response
app.use((err, req, res, next) => {
  logger.error({ err, req });       // full details in logs
  res.status(500).json({ error: 'Internal server error' });  // generic to client
});
```

--

## References & Tools

| Resource | Details |
|---|---|
| [OWASP Error Handling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html) | Patterns for safe error handling |
| SonarQube | Detects swallowed exceptions, info disclosure |
| Semgrep | Custom rules for fail-open patterns |
| OWASP ZAP | Triggers error conditions, checks responses |
