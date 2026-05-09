## API7:2023 — Server-Side Request Forgery
**🟡 Medium** | CWE-918

> The API fetches a remote resource from a **user-controlled URL**
> without validating the destination.

Note: SSRF is particularly dangerous in cloud environments where the metadata endpoint (169.254.169.254) provides IAM credentials without authentication. It's listed separately in the API Top 10 because webhooks, integrations, and fetch-proxy APIs are extremely common API patterns.

--

## How It Works

**Cloud metadata endpoint — IAM credential theft:**

```http
# API accepts any URL for a "preview" feature
POST /api/preview
{ "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/prod-role" }

# Response:
{
  "Code": "Success",
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "wJalrXUtnFEMI...",   ← real IAM credentials!
  "Token": "AQoD...",
  "Expiration": "2024-01-20T12:00:00Z"
}
```

**Internal service enumeration:**
```http
POST /api/webhook/test
{ "url": "http://10.0.0.1:6379" }   ← Redis, no auth
{ "url": "http://10.0.0.5:9200" }   ← Elasticsearch
{ "url": "http://db.internal:5432" } ← PostgreSQL
```

Note: SSRF = Server-Side Request Forgery — server fetches a URL controlled by the attacker. IAM = Identity and Access Management. The cloud metadata endpoint 169.254.169.254 is a link-local address accessible only from within the cloud instance — attackers reach it by making the server fetch it on their behalf. IMDSv2 (Instance Metadata Service v2) requires a session token to access metadata, mitigating most SSRF exploits.

--

## Real-World Examples

**Capital One (2019)**
- SSRF via misconfigured WAF → EC2 metadata endpoint
- Attacker retrieved S3 credentials, accessed 100M+ records
- **Impact**: $80M fine; landmark cloud SSRF case

**GitLab (2021) — CVE-2021-22214**
- SSRF in CI/CD webhook feature allowed internal network scanning
- Internal services (Redis, Gitlab internal API) accessible
- **Impact**: Critical severity, auth bypass possible

Note: The Capital One attacker (Paige Thompson, a former AWS employee) knew the cloud metadata endpoint pattern precisely — she had inside knowledge of AWS infrastructure. The WAF was configured to proxy requests but not block outbound connections to internal IP ranges. GitLab CVE-2021-22214 was SSRF via the CI/CD job callback URL — an attacker could register a runner and have it call internal services.

--

## Mitigation

1. **Whitelist** allowed domains/IPs — never allow arbitrary user URLs
2. **Block all internal ranges** explicitly at DNS + network level
3. Disable HTTP redirects, or validate each redirect destination

```python
import ipaddress, socket, re
from urllib.parse import urlparse

BLOCKED_RANGES = [
    ipaddress.ip_network('169.254.0.0/16'),  # cloud metadata
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
]

def validate_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        return False
    ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
    return not any(ip in net for net in BLOCKED_RANGES)
```

Note: DAST = Dynamic Application Security Testing — tests a running application. Burp Collaborator is an out-of-band detection service: it generates unique DNS/HTTP endpoints you can embed in payloads; when the server makes a request to them, Burp detects the callback even if the server's response doesn't reveal what it fetched.

--

## References & Tools

| Resource | Details |
|---|---|
| [OWASP SSRF Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) | Full prevention guide |
| AWS IMDSv2 | Metadata endpoint with token auth (mitigates basic SSRF) |
| OWASP ZAP | DAST scanner for SSRF |
| Burp Collaborator | Out-of-band SSRF detection |
