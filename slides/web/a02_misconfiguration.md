## A02:2025 — Security Misconfiguration
CWE-16 / CWE-611

> Insecure defaults, incomplete setup, unnecessary features, missing hardening.
> Found in **90%** of tested applications. Moved from #5 → #2 in 2025.

Note: Includes XXE (XML External Entities) which was its own category in 2017. Cloud misconfigurations are a major driver of the ranking jump.

--

## How It Works

**Default credentials left enabled:**
```bash
# Default admin panel — still accessible in prod
curl http://app.example.com/admin   # Returns 200 with login form
# Credentials: admin / admin  ← never changed
```

**Missing security headers** — browser protections disabled by omission:
```http
# Response headers (bad)
HTTP/1.1 200 OK
Server: Apache/2.4.41 (Ubuntu)   ← version disclosure
X-Powered-By: Express            ← framework disclosure
# Missing: HSTS, CSP, X-Frame-Options, X-Content-Type-Options
```

Note: XXE = XML External Entities — an XML parsing attack that was its own OWASP category in 2017, now folded into A02. HSTS = HTTP Strict Transport Security — instructs browsers to always use HTTPS. CSP = Content Security Policy — controls which scripts, styles, and origins the browser trusts.

--

## Real-World Examples

**Capital One (2019) — S3 misconfiguration**
- AWS WAF misconfigured; SSRF allowed access to EC2 metadata endpoint
- Attacker retrieved IAM credentials, accessed 100M+ customer records
- **Impact**: $80M fine, 100M+ records

**Verkada (2021)**
- Default "super-admin" credentials exposed on the internet
- Attackers accessed 150,000+ security cameras (hospitals, Tesla, jails)
- **Impact**: live footage from sensitive locations

Note: WAF = Web Application Firewall. SSRF = Server-Side Request Forgery — server fetches a URL the attacker controls. IAM = Identity and Access Management — AWS's permission system. EC2 metadata endpoint (169.254.169.254) provides IAM credentials without authentication to anything running on the instance. S3 = Amazon Simple Storage Service.

--

## Mitigation

1. Remove **unnecessary features**, debug endpoints, default accounts
2. Implement a **hardened baseline** applied identically across all environments
3. Set **security headers** on every response

```nginx
# nginx.conf — security headers
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Content-Security-Policy "default-src 'self'" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
server_tokens off;  # hide nginx version
```

Note: IaC = Infrastructure as Code — Terraform, Helm, Kubernetes manifests. Checkov and Trivy scan these files for misconfigurations before deployment.

--

## References & Tools

| Resource | Details |
|---|---|
| [OWASP Security Headers](https://owasp.org/www-project-secure-headers/) | Header reference |
| [SecurityHeaders.com](https://securityheaders.com) | Free header scanner |
| [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) | Hardening guides per technology |
| Trivy / Checkov | Scans IaC (Terraform, Helm, Kubernetes) for misconfigs |
| Lynis | Server hardening audit — Linux security baseline |
| SonarQube | Detects hardcoded credentials and weak config values in source |
