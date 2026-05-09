## A08:2025 — Software & Data Integrity Failures
**🟡 Medium** | CWE-494 · CWE-502 · CWE-565

> Assumptions about software updates, CI/CD pipelines,  
> and critical data without verifying integrity.

Note: Covers insecure deserialization (moved from its own 2017 category), unsigned updates, compromised artifact repositories, and untrusted CI/CD pipelines.

--

## How It Works

**Insecure deserialization — arbitrary code execution:**
```java
// VULNERABLE — Java deserialization of untrusted data
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
Object obj = ois.readObject();  // ← executes code during deserialization
// Attacker sends crafted payload → Remote Code Execution
```

**Unsigned npm package — typosquatting:**
```bash
npm install crossenv    # typo for 'cross-env'
# 'crossenv' (2017): exfiltrated env vars (AWS keys, DB passwords)
# to attacker's server on install
```

**Insecure CI/CD — secrets in build logs:**
```yaml
# VULNERABLE — secret printed in CI output
- run: echo "DB_PASSWORD=${{ secrets.DB_PASS }}" && npm test
```

Note: Deserialization = converting stored/transmitted bytes back into an object. Java's ObjectInputStream executes code during deserialization, so a crafted payload can trigger arbitrary method calls — RCE = Remote Code Execution. CI/CD = Continuous Integration / Continuous Deployment — the automated build, test, and release pipeline.

--

## Real-World Examples

**SolarWinds (2020)**
- Build pipeline compromised; malicious code inserted into signed Orion updates
- Distributed to 18,000+ customers including US government
- **Impact**: 9 months undetected, access to Treasury, Commerce, DHS

**event-stream npm package (2018)**
- Malicious maintainer added dependency `flatmap-stream` targeting Bitcoin wallets
- Downloaded 8M+ times before discovery
- **Impact**: Targeted theft from Copay Bitcoin wallet users

Note: The SolarWinds SUNBURST backdoor was inserted by the SVR (Russian foreign intelligence) into the legitimate Orion build process — the resulting DLL was cryptographically signed by SolarWinds itself, making detection extremely difficult. The event-stream attack targeted Copay wallet — the malicious code only activated when the npm package detected it was running in the Copay app context.

--

## Mitigation

1. **Verify package integrity** — use lockfiles and checksums
2. **Sign artifacts** in CI/CD — verify before deployment
3. **Never deserialize** untrusted data; use safe formats (JSON with schema validation)

```bash
# Verify npm package integrity
npm ci   # uses package-lock.json — fails if checksums don't match

# Generate and verify checksums
sha256sum dist/app.js > dist/app.js.sha256
sha256sum -c dist/app.js.sha256
```

```yaml
# GitHub Actions — sign with cosign
- name: Sign container image
  run: |
    cosign sign --key cosign.key \
      ${{ env.REGISTRY }}/${{ env.IMAGE }}@${{ steps.build.outputs.digest }}
```

Note: SLSA = Supply-chain Levels for Software Artifacts (pronounced "salsa") — a Google-originated framework with four levels of build provenance. Sigstore/Cosign = tools for signing software artifacts with cryptographic signatures tied to developer identity. `npm ci` uses package-lock.json checksums — it fails if any package doesn't match.

--

## References & Tools

| Resource | Details |
|---|---|
| [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html) | Safe deserialization |
| [Sigstore / Cosign](https://www.sigstore.dev) | Artifact signing & verification |
| `npm ci` | Integrity-verified install |
| Snyk | Detects malicious / compromised packages |
| [SLSA Framework](https://slsa.dev) | Supply chain security levels |
