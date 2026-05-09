## Key Takeaways

**Shift Left** — catch security issues before they reach production

- Most vulnerabilities are **architectural** (access control, design) not just coding bugs
- **Dependencies** are your biggest blind spot — scan them continuously
- **APIs** have their own attack surface, separate from web apps
- **LLM/Agentic** systems introduce brand-new trust boundaries

> Security is not a feature — it's a property of the whole system.

--

## Toolchain Summary

| Phase | Tool | Covers |
|---|---|---|
| Code | SonarQube / Semgrep | Injection, Auth, Crypto |
| Dependencies | `npm audit`, Snyk, Dependabot | Vulnerable Components, Supply Chain |
| Secrets | GitGuardian, TruffleHog | Exposed credentials |
| DAST | OWASP ZAP, Burp Suite | Injection, SSRF, Misconfig |
| API | 42Crunch, Postman | BOLA, Auth, Schema drift |
| Container | Trivy, Cosign | Supply Chain, Misconfig |
| Mobile | MobSF, apktool | Credential leaks, Binary |
| LLM | LLM Guard, Garak | Prompt injection, Jailbreaks |

--

## References

| Resource | URL |
|---|---|
| OWASP Top 10:2025 | owasp.org/Top10/2025/ |
| OWASP API Security:2023 | owasp.org/API-Security/ |
| OWASP Mobile Top 10:2024 | owasp.org/www-project-mobile-top-10/ |
| OWASP LLM Top 10:2025 | genai.owasp.org/llm-top-10/ |
| OWASP Cheat Sheet Series | cheatsheetseries.owasp.org |
| Snyk Learn | learn.snyk.io/learning-paths/owasp-top-10/ |
| CWE Top 25 | cwe.mitre.org/top25/ |
