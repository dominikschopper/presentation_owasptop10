## API3:2023 — Broken Object Property Level Authorization
**🟠 High** | CWE-213 / CWE-915

> APIs expose **too many properties** in responses (over-exposure),
> or accept **properties they shouldn't** in requests (mass assignment).

Note: Merges two categories from 2019: "Excessive Data Exposure" (returning more fields than needed) and "Mass Assignment" (accepting more fields than intended). Both stem from trusting serialization frameworks too much.

--

## How It Works

**Over-exposure — returning sensitive fields:**

```json
// Request: GET /api/users/42
// Response includes fields the client never needs:
{
  "id": 42,
  "email": "alice@example.com",
  "name": "Alice",
  "passwordHash": "$2b$12$...",   ← sensitive!
  "isAdmin": false,                ← sensitive!
  "internalScore": 847,            ← sensitive!
  "stripeCustomerId": "cus_..."    ← sensitive!
}
```

**Mass assignment — client sets privileged fields:**
```json
// PATCH /api/users/42
// Client sends:
{ "name": "Alice", "isAdmin": true, "creditBalance": 99999 }
// ORM auto-maps ALL fields → user is now admin with free credits
```

Note: BOPLA = Broken Object Property Level Authorization — merges two 2019 categories: "Excessive Data Exposure" (returning more fields than needed) and "Mass Assignment" (accepting more fields than intended from a request). DTO = Data Transfer Object — an object with only the fields explicitly declared for a given operation.

--

## Real-World Examples

**GitHub (2012) — Mass Assignment**
- Rails `attr_accessible` not set; attacker added SSH public key to another user's account

- Used to push code to the Rails project itself
- **Impact**: Demonstrated mass assignment risk; led to Rails changing defaults

**HackerOne (2021)**
- API response included internal field `is_verified`
- Enumeration + field revealed unverified security researchers' reports
- **Impact**: Confidential vulnerability reports exposed

Note: The GitHub 2012 incident was discovered and disclosed by security researcher Egor Homakov, who pushed code to the Rails repository itself to demonstrate the issue. This led to Ruby on Rails changing its defaults to require explicit strong parameters, and GitHub patched within hours. HackerOne's 2021 over-exposure exposed confidential (undisclosed) vulnerability reports from security researchers — a significant trust breach for a bug bounty platform.

--

## Mitigation

1. **Whitelist** exactly which fields are returned per response — never serialize full models
2. **Whitelist** which fields can be written — reject unexpected properties
3. Use **DTOs** (Data Transfer Objects) to define input/output contracts

```python
# FIXED — explicit response schema with Pydantic
class UserPublicResponse(BaseModel):
    id: int
    name: str
    email: str
    # passwordHash, isAdmin, stripeCustomerId NOT included

@app.get('/api/users/{user_id}', response_model=UserPublicResponse)
def get_user(user_id: int):
    return db.get(User, user_id)  # Pydantic filters to declared fields
```

```python
# FIXED — whitelist writable fields
class UserUpdateRequest(BaseModel):
    name: str | None = None
    email: str | None = None
    # isAdmin, creditBalance NOT allowed — rejected automatically
```

Note: ORM = Object-Relational Mapper. When ORMs serialize entire model objects to JSON, every database column is exposed — including internal fields never intended for clients. Pydantic (Python), Marshmallow (Python), Zod (TypeScript) enforce explicit field declarations at the schema level.

--

## References & Tools

| Resource | Details |
|---|---|
| [OWASP Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html) | Prevention |
| Pydantic / Marshmallow / Zod | Schema-driven serialization |
| SonarQube | Detects unfiltered serialization |
| 42Crunch | API schema conformance testing |
