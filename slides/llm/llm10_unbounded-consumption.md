## LLM10:2025 — Unbounded Consumption
**🟡 Medium**

> LLM operations with no resource limits enable DoS attacks,  
> runaway costs, and service degradation.

Note: Unlike traditional DoS (bandwidth flooding), LLM consumption attacks are stealthy and expensive. A single carefully crafted prompt can consume 10,000× more compute than a normal request. And because API usage is billed per token, attackers can weaponize cost against you.

--

## How It Works

**Token flood — force maximum output:**

```
User: "Write the complete works of Shakespeare, every play and sonnet,
       in its entirety, starting from the beginning..."

→ LLM tries to comply → generates millions of tokens
→ $500+ API cost for a single request
→ Timeout/OOM if limits not set
```

**Infinite reasoning loop (chain-of-thought):**
```python
# VULNERABLE — no max_tokens limit
response = openai.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": adversarial_prompt}],
    # No max_tokens → model can run indefinitely
)
```

**Context window exhaustion:**
```
Attacker sends extremely long document (100K tokens) for "summarization"
→ Fills entire context window
→ Model takes 30+ seconds to process
→ Server thread held; 100 simultaneous requests → DoS
```

Note: Token = the basic processing unit of an LLM — roughly ¾ of an English word. GPT-4 charges ~$0.03 per 1K output tokens; a 100K-token response costs ~$3. DoS = Denial of Service. OOM = Out of Memory. Context window = the maximum number of tokens an LLM can process in one request (e.g. 128K for GPT-4o).

--

## Real-World Examples

**OpenAI API key theft + abuse (recurring 2023–2024)**
- Stolen keys used to run large-scale LLM workloads (model training, bulk generation)
- Victims receive monthly bills of $10,000–$100,000
- **Impact**: Stripe/OpenAI chargebacks; account termination; financial loss

**Prompt-based DoS against internal tools (2024)**
- Internal AI assistants with no rate limiting crashed under coordinated token-flood requests
- Engineering teams took hours to identify the cause
- **Impact**: Internal tooling outages; developer productivity loss

Note: OpenAI provides hard billing limits per organization — set them. AWS Bedrock Guardrails can enforce per-request token limits at the infrastructure level, outside the application code. LangSmith (LangChain's observability product) and Langfuse (open-source alternative) track token usage, cost, and latency per request, enabling anomaly alerts when usage spikes unexpectedly.

--

## Mitigation

1. Always set **`max_tokens`** on every LLM API call
2. Implement **per-user token budgets** (daily/monthly limits)
3. Add **request timeouts** and monitor spend in real time

```python
import openai
from functools import wraps
import redis

r = redis.Redis()
DAILY_TOKEN_LIMIT = 10_000  # per user

def with_token_budget(user_id: str):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            key = f"tokens:{user_id}:{date.today()}"
            used = int(r.get(key) or 0)
            if used >= DAILY_TOKEN_LIMIT:
                raise HTTPException(429, "Daily token limit exceeded")
            return await func(*args, **kwargs)
        return wrapper
    return decorator

async def call_llm(user_id: str, prompt: str) -> str:
    response = await openai.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=2000,         # ← always set this!
        timeout=30,              # ← and this!
    )
    tokens_used = response.usage.total_tokens
    r.incrby(f"tokens:{user_id}:{date.today()}", tokens_used)
    r.expire(f"tokens:{user_id}:{date.today()}", 86400)
    return response.choices[0].message.content
```

Note: Per-user token budgets stored in Redis (or any fast key-value store) enable real-time enforcement across multiple server instances. The Redis `INCRBY` + `EXPIRE` pattern creates a sliding daily window without a cron job. Hard billing limits (set at the OpenAI organization level) are the last line of defense — set them conservatively.

--

## References & Tools

| Resource | Details |
|---|---|
| [OWASP LLM10 Guide](https://genai.owasp.org/llmrisk/llm10-unbounded-consumption/) | Official guidance |
| OpenAI Usage Limits | Hard billing limits per organization |
| [AWS Bedrock Guardrails](https://aws.amazon.com/bedrock/guardrails/) | Managed throttling for LLM APIs |
| LangSmith / Langfuse | LLM observability + cost monitoring |
