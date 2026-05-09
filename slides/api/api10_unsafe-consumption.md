## API10:2023 — Unsafe Consumption of APIs
**🟡 Medium** | CWE-345 · CWE-346

> Applications implicitly trust third-party API responses  
> and process them without validation — treating **external** data as safe.

Note: The inverse of the other categories: instead of attackers abusing your API, this is about your code unsafely consuming someone else's API. A compromised third-party API becomes an attack vector into your system.

--

## How It Works

**Trusting payment API response without verification:**

```javascript
// VULNERABLE — trusting third-party response
const response = await paymentGateway.verify(transactionId);
if (response.status === 'paid') {     // ← what if API is compromised?
  await fulfillOrder(orderId);         // or response is manipulated?
}
// Attacker intercepts/modifies API response → free orders
```

**Injecting via third-party data:**
```python
# VULNERABLE — using external API data in SQL
weather = requests.get(f'https://weather-api.com/city/{city}').json()
# weather_api is compromised — returns: London'; DROP TABLE users; --
db.execute(f"SELECT * FROM forecasts WHERE city='{weather['city']}'")
```

Note: This is the inverse of other API vulnerabilities — instead of attackers abusing your API, your code unsafely consumes someone else's API. A compromised or misconfigured third-party service becomes an attack vector into your application. The principle: treat all external API responses as untrusted input, just like user input.

--

## Real-World Examples

**British Airways (2018) — Magecart / third-party script**
- Attacker compromised a third-party chatbot script loaded by BA's payment page
- Script exfiltrated credit card data to attacker's server
- **Impact**: 500,000 customer payment details; £183M GDPR fine (later reduced to £20M)

**Target (2013) — HVAC Vendor Compromise**
- Attackers compromised Target's HVAC vendor, used their portal access to reach payment systems
- **Impact**: 40M credit cards; $292M in breach costs

Note: Magecart is a collective name for several criminal groups that inject skimming scripts into e-commerce payment pages — either by compromising third-party scripts or directly. BA's initial GDPR fine of £183M was the largest ever at the time; it was reduced on appeal to £20M. SRI = Subresource Integrity — an HTML attribute that lets browsers verify a CDN-loaded script hasn't changed. HMAC = Hash-based Message Authentication Code — used by Stripe, GitHub, Twilio to sign webhook payloads, allowing receivers to verify the payload wasn't tampered with.

--

## Mitigation

1. **Validate all external data** — treat third-party API responses as untrusted input
2. Use **cryptographic verification** (HMAC, webhook signatures) for critical flows
3. Implement **circuit breakers** — fail safely if a third-party API behaves unexpectedly

```javascript
// FIXED — verify webhook signature (Stripe pattern)
const stripe = require('stripe')(process.env.STRIPE_SECRET);

app.post('/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.WEBHOOK_SECRET);
  } catch (err) {
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }
  // Now safe to process — signature verified
  if (event.type === 'payment_intent.succeeded') { ... }
});
```

Note: Circuit breaker = a design pattern (from electrical engineering) that detects failures and stops making requests to a failing service, preventing cascade failures. resilience4j (Java) and Polly (.NET) implement circuit breakers, retries with backoff, and timeouts.

--

## References & Tools

| Resource | Details |
|---|---|
| [OWASP Third Party JS](https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html) | External script security |
| Subresource Integrity (SRI) | Hash-verify CDN scripts |
| Webhook signature verification | Stripe, GitHub, Twilio all provide HMAC |
| resilience4j / Polly | Circuit breaker libraries |
