## API5:2023 — Broken Function Level Authorization
**🟠 High** | CWE-284 / CWE-285

> APIs don't properly restrict which **functions** a user can invoke.
> Regular users call admin endpoints and succeed.

Note: BFLA = Broken Function Level Authorization. Similar to BOLA but about *functions* not *objects*. BOLA = "can I read someone else's data?", BFLA = "can I perform an action I'm not allowed to do?" Often discovered by reading API docs or JavaScript source that lists admin endpoints.

--

## How It Works

```http
# Normal user flow
GET  /api/v1/products          → list products
POST /api/v1/cart/add          → add to cart
POST /api/v1/orders            → create order

# Attacker reads JS source, finds admin endpoints:
DELETE /api/v1/admin/users/99  Authorization: Bearer <regular_user_token>
→ 200 OK   ← admin endpoint not role-checked!

POST /api/v1/admin/discount    Authorization: Bearer <regular_user_token>
{ "code": "FREE100", "percent": 100 }
→ 200 OK   ← discount created!
```

**HTTP method confusion:**

```http
GET  /api/orders/42   → 200 OK (read allowed)
PUT  /api/orders/42   → 403 Forbidden (update blocked)
PATCH /api/orders/42  → 200 OK (← PATCH not checked separately!)
```

Note: HTTP method confusion occurs when authorization is checked for PUT but not PATCH, or GET but not HEAD. The server may route both to the same handler but skip the authorization middleware for the unchecked method.

--

## Real-World Examples

**Bumble (2020)**
- API function to retrieve nearby users had no rate limit or distance enforcement

Note: The Bumble BFLA was discovered by security researcher Robert Baptiste (Elliot Alderson). The vulnerability also exposed exact location coordinates via trilateration — three API calls with spoofed locations could calculate a user's precise position. Peloton's unauthenticated API was disclosed by security researcher Jan Masters; Peloton initially disputed the severity before patching.
- Regular users could call paid-feature "travel mode" endpoints for free
- **Impact**: Location data of all users exploitable; premium features bypassed

**Peloton (2021)**
- Unauthenticated API endpoint returned any user's private workout data and profile
- No authentication required on user data endpoint
- **Impact**: 4M+ user profiles accessible without login

Note: The Bumble BFLA was discovered by security researcher Robert Baptiste (Elliot Alderson). The vulnerability also exposed exact location coordinates via trilateration — three API calls with spoofed locations could calculate a user's precise position. Peloton's unauthenticated API was disclosed by security researcher Jan Masters; Peloton initially disputed the severity before patching.

--

## Mitigation

1. **Enumerate all API functions** and map each to required roles
2. Apply **deny-by-default** at the framework level — authorization middleware runs first
3. Restrict **all HTTP methods** explicitly, not just GET/POST

```python
# FIXED — explicit role check on every admin function
from functools import wraps

def require_role(*roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if current_user.role not in roles:
                abort(403)
            return f(*args, **kwargs)
        return wrapper
    return decorator

@app.delete('/api/admin/users/<user_id>')
@require_role('admin', 'superadmin')   # ← explicit authorization
def delete_user(user_id):
    ...
```

Note: OPA = Open Policy Agent — policies written in Rego (a declarative language) evaluated against request context. Policies can be tested separately from application code and updated without redeployment. "Deny by default" at the framework level means the absence of an explicit grant is a denial, not an allow.

--

## References & Tools

| Resource | Details |
|---|---|
| [OWASP BFLA Guide](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/) | Official guide |
| Casbin / OPA (Open Policy Agent) | Policy-based authorization |
| 42Crunch | API schema + auth testing |
| Postman | Manual BFLA testing across roles |
