## A09:2025 — Security Logging & Monitoring Failures
**🟡 Medium** | CWE-117 · CWE-223 · CWE-532 · CWE-778

> Without adequate logging and alerting, attacks go undetected.  
> Average time to detect a breach: **204 days** (IBM 2023).

Note: This category is about detection capability, not prevention. Even if you're breached, good logging limits damage through faster detection and better forensics.

--

## How It Works

**What typically isn't logged (but should be):**
```
✗ Failed login attempts (or logged without alert threshold)
✗ Privilege escalation events
✗ Bulk data access (1000 records in 1 second)
✗ Access to sensitive endpoints from unusual IPs
✗ Configuration changes
✗ API calls returning 403/401 (authorization failures)
```

**Logs that help attackers when exposed:**
```
ERROR 2024-01-15 NullPointerException at com.example.auth.JwtFilter:47
  at ...UserRepository.findById(UserRepository.java:23)
  SQL: SELECT * FROM users WHERE id=?  ← reveals stack, ORM, SQL
```

Note: SIEM = Security Information and Event Management — platform that aggregates, correlates, and alerts on security logs from multiple sources. Structured logging = writing logs as machine-parseable JSON rather than free-form text, enabling automated analysis. The "204 days" IBM figure is from the IBM Cost of a Data Breach Report 2023.

--

## Real-World Examples

**Target (2013)**
- FireEye security tool detected malware — alert was ignored
- Attackers had 2+ weeks to exfiltrate 40M credit card numbers
- **Impact**: $162M in breach costs; CEO and CIO resigned

**Equifax (2017)**
- TLS inspection certificate expired → traffic not inspected for 19 months
- Breach undetected for 78 days after initial compromise
- **Impact**: 147M records, $700M settlement

Note: Target's security team in Bangalore received FireEye alerts but the US team did not act on them — a monitoring failure, not a detection failure. The TLS certificate expiry at Equifax meant traffic wasn't inspected by their network security appliance for 19 months — the breach was only discovered when the certificate was renewed and suddenly suspicious traffic became visible.

--

## Mitigation

1. Log **all security events** in a structured (JSON), tamper-resistant format
2. **Ship logs off the server** — attackers delete local logs first
3. Alert on anomalies — failed logins, bulk access, auth failures

```javascript
// Structured security logging (winston)
const logger = winston.createLogger({
  format: winston.format.json(),
  transports: [new winston.transports.Console()],
});

function logAuthFailure(req, reason) {
  logger.warn({
    event: 'auth_failure',
    ip: req.ip,
    username: req.body.username,
    reason,
    timestamp: new Date().toISOString(),
    userAgent: req.headers['user-agent'],
  });
}
```

--

## References & Tools

| Resource | Details |
|---|---|
| [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) | What & how to log |
| [OWASP Application Logging Vocabulary](https://owasp.org/www-project-application-logging-vocabulary/) | Standard event names |
| ELK Stack (Elasticsearch, Logstash, Kibana) | Log aggregation + dashboards |
| Splunk / Datadog / Grafana Loki | SIEM and alerting |
| Fail2ban | Auto-block IPs on threshold |

Note: ELK = Elasticsearch (search/store), Logstash (ingest/parse), Kibana (visualize) — the classic open-source log stack. Fail2ban monitors log files for failed auth patterns and automatically adds firewall rules to block offending IPs. Splunk and Datadog are commercial SIEM alternatives with built-in anomaly detection.
