## API9:2023 — Improper Inventory Management
**🟡 Medium** | CWE-1059

> Unknown, undocumented, or forgotten APIs — "shadow APIs" —
> are unpatched and expose the same data as production APIs.

Note: Modern organizations often have dozens of API versions, partner APIs, internal APIs, and test APIs running simultaneously. Security teams often don't know they all exist.

--

## How It Works

**Deprecated API version — patched in v2, forgotten in v1:**

```http
# v2 (current) — patched SQL injection
POST /api/v2/users/search   → 422 (injection attempt blocked)

# v1 (old, forgotten) — still running!
POST /api/v1/users/search   → 200 (vulnerable, unpatched)

# Attacker discovers v1 by:
# - Reading old documentation / swagger files
# - Trying /v1/, /v0/, /legacy/, /internal/
# - Checking git history for old API paths
```

**Test API with lower security in production:**
```plain
https://api.example.com/         → production (auth required)
https://test-api.example.com/    → test environment (no auth!)
https://staging.example.com/api/ → staging (same prod database!)
```

Note: Shadow API = an endpoint not tracked in the official API inventory — typically a forgotten v1, a test environment left running, or an internal API that became accessible from the outside. API sprawl is common in organizations with multiple teams deploying independently.

--

## Real-World Examples

**Peloton (2021)**
- Undocumented internal API exposed workout stats and user profiles
- No authentication required — discovered by reading mobile app network traffic
- **Impact**: 4M+ users' private data accessible without login

**Bumble (2020)**
- Researchers discovered hidden API endpoints by analyzing the mobile app's binary
- Endpoints lacked the same rate limiting as documented APIs
- **Impact**: Full user data and location enumeration

Note: Both Peloton and Bumble appear in API5 (BFLA) and API9 (Inventory) because the vulnerabilities had elements of both — undocumented endpoints that also lacked authorization. OpenAPI's `deprecated: true` and `x-sunset` extension are machine-readable markers used by API gateways and developer portals to surface deprecation warnings to API consumers.

--

## Mitigation

1. Maintain a **complete API inventory** — use discovery tools to find shadow APIs
2. Define and enforce **deprecation timelines** — fully decommission old versions
3. Apply **identical security controls** across all versions and environments

```yaml
# OpenAPI spec — document ALL versions, mark deprecated
openapi: 3.1.0
info:
  version: 2.0.0

paths:
  /v1/users/search:
    post:
      deprecated: true    # ← marks as deprecated in tooling
      description: "Deprecated. Use /v2/users/search. Removed 2025-06-01."
      x-sunset: "2025-06-01"   # ← machine-readable removal date

  /v2/users/search:
    post:
      summary: "Search users (current)"
```

--

## References & Tools

| Resource | Details |
|---|---|
| [OWASP Inventory Guide](https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/) | Official guide |
| 42Crunch / Swagger Inspector | API discovery and documentation |
| Postman | API catalog and testing |
| AWS API Gateway / Kong | Centralized API management + inventory |
