## API4:2023 — Unrestricted Resource Consumption
**🟠 High** | CWE-307 · CWE-400 · CWE-770

> APIs with no rate limits, timeouts, or resource caps  
> are vulnerable to DoS, brute force, and runaway cost attacks.

Note: Renamed from "Lack of Resources & Rate Limiting" (2019). Now explicitly includes excessive API costs (LLM tokens, cloud compute) as a form of resource consumption attack.

--

## How It Works

**No pagination limits — memory exhaustion:**

```http
GET /api/orders?page=1&limit=999999999
→ Server loads ALL orders into memory → OOM crash
```

**Expensive query with no timeout:**
```python
# VULNERABLE — no timeout on slow query
@app.get('/api/analytics/report')
def get_report(start: date, end: date):
    # date range of 10 years → full table scan
    return db.execute('SELECT * FROM events WHERE ts BETWEEN ? AND ?', start, end)
```

**Brute force OTP — no rate limit:**
```bash
# 6-digit OTP = 1,000,000 combinations
# At 100 req/sec with no limit: cracked in ~167 minutes
for code in $(seq -w 000000 999999); do
  curl -X POST /api/verify-otp -d "code=$code" &
done
```

Note: OOM = Out of Memory — server process killed by the OS when heap is exhausted. OTP = One-Time Password — typically 6 digits, making brute force feasible without rate limiting (10^6 = 1,000,000 combinations). DoS = Denial of Service.

--

## Real-World Examples

**Venmo Public API (2019)**
- No rate limiting on public transaction feed
- Researcher scraped 207M transactions in under a week
- **Impact**: All public transaction data bulk-extracted, privacy violation

Note: The Venmo scraping was performed by privacy researcher Dan Salmon, who published the dataset to demonstrate that "public by default" combined with no rate limiting creates a mass surveillance risk. OpenAI's API key theft problem is structural — keys are long-lived, and billing alerts often only trigger after $1,000+ has been spent.

**OpenAI API abuse (recurring)**
- Stolen API keys used to run large workloads
- **Impact**: Victims receive $10K–$100K cloud bills before detection

Note: The Venmo scraping was performed by privacy researcher Dan Salmon, who published the dataset to demonstrate that "public by default" combined with no rate limiting creates a mass surveillance risk. OpenAI's API key theft problem is structural — keys are long-lived, and billing alerts often only trigger after $1,000+ has been spent.

--

## Mitigation

1. **Rate limit** all endpoints — per user, per IP, and globally
2. Set **maximum payload and response sizes**
3. Implement **timeouts** on all queries and external calls

```javascript
// express-rate-limit — per route limits
const rateLimit = require('express-rate-limit');

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,   // 1 minute
  max: 100,               // 100 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests' },
});

const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 5,                     // only 5 OTP attempts
});

app.use('/api/', apiLimiter);
app.use('/api/verify-otp', otpLimiter);
```

--

## References & Tools

| Resource | Details |
|---|---|
| [OWASP Rate Limiting Guidance](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/) | Official guide |
| express-rate-limit | Node.js rate limiting |
| slowapi | Python/FastAPI rate limiting |
| Kong / AWS API Gateway | Infrastructure-level rate limiting |
| Cloudflare Rate Limiting | Edge-level protection |
