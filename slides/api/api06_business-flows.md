## API6:2023 — Unrestricted Access to Sensitive Business Flows
**🟠 High** | CWE-770 / CWE-799

> APIs expose business-critical flows without compensating controls.
> Attackers automate **intended functionality** at inhuman scale.

Note: Unlike DoS (resource consumption), this is about abusing perfectly valid functionality — buying tickets, creating accounts, posting reviews — but doing it faster and at more scale than any human could.

--

## How It Works

**Ticket scalping via automated checkout:**
```python
# Attacker script — hundreds of parallel requests
import asyncio, aiohttp

async def buy_ticket(session, event_id):
    return await session.post(f'/api/events/{event_id}/purchase',
                              json={'quantity': 10})

async def main():
    async with aiohttp.ClientSession() as s:
        tasks = [buy_ticket(s, 'concert-2024') for _ in range(500)]
        results = await asyncio.gather(*tasks)
# All inventory bought before humans can react
```

**Account creation for spam:**

```bash
# Free tier gives 100 API credits per account
# Script creates 10,000 accounts → 1M free credits
```

Note: This category is about automating *intended* functionality at inhuman scale — not exploiting a bug. The API is working correctly; the missing control is a business-logic limit. Scalping bots typically use residential proxy networks to distribute requests across many IPs, evading IP-based rate limits.

--

## Real-World Examples

**Ticketmaster / StubHub (recurring)**
- Bots purchase high-demand tickets within milliseconds of release
- Queue systems bypassed via API calls instead of web flow
- **Impact**: Tickets appear on resale markets immediately at 10x price

**COVID Vaccine Slot Bots (2021)**
- Bots monitored and booked vaccine appointment APIs
- Real citizens unable to book slots that were immediately resold
- **Impact**: Systemic inequity in access to public health resources

Note: The UK passed the Digital Economy Act 2017 and the US passed the BOTS Act 2016 to criminalize ticket scalping bots — demonstrating that some API abuse issues require legislative intervention, not just technical controls.

--

## Mitigation

1. **Detect bot patterns** — identical timing, sequential IDs, missing browser fingerprint
2. Add **friction** to sensitive flows — CAPTCHA, delays, confirmations
3. Implement **business-logic rate limits** separate from API rate limits

```python
# Business-logic limits (separate from API rate limit)
MAX_TICKETS_PER_USER_PER_EVENT = 4
MAX_ACCOUNTS_PER_IP_PER_DAY = 2
MAX_PURCHASES_PER_HOUR = 3

@app.post('/api/events/{event_id}/purchase')
@require_auth
def purchase_ticket(event_id, user=current_user, quantity: int = 1):
    existing = db.count_user_tickets(user.id, event_id)
    if existing + quantity > MAX_TICKETS_PER_USER_PER_EVENT:
        raise HTTPException(422, 'Purchase limit exceeded')
    ...
```

Note: CAPTCHA = Completely Automated Public Turing test to tell Computers and Humans Apart. reCAPTCHA v3 returns a risk score (0.0–1.0) without a visible challenge — you choose the threshold at which to block or add friction.

--

## References & Tools

| Resource | Details |
|---|---|
| [OWASP Business Logic Cheat Sheet](https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/) | Official guide |
| Google reCAPTCHA v3 | Invisible bot scoring |
| Cloudflare Bot Management | Edge-level bot detection |
| Arkose Labs / Imperva | Behavioral bot analytics |
