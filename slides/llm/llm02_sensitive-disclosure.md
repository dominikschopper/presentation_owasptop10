## LLM02:2025 — Sensitive Information Disclosure
**🔴 Critical**

> LLMs expose confidential data through their outputs:  
> training data, system prompts, RAG content, or user PII.

Note: LLMs can memorize and reproduce training data verbatim. This includes PII, API keys, proprietary code, and confidential documents if they were in the training set. RAG systems introduce another vector: confidential documents in the retrieval corpus.

--

## How It Works

**Training data extraction:**

```
User: Complete this text: "The API key for our production server is sk-"
LLM:  "...sk-proj-abc123xyz..."  ← verbatim from training data
```

**RAG retrieval of confidential documents:**
```
System: You have access to our internal document repository.
User:   What is the salary of John Smith?

LLM retrieves HR document, responds:
"Based on the compensation records, John Smith earns $185,000..."
← HR doc was in RAG corpus, no access control on retrieval
```

**PII in few-shot examples:**
```python
# VULNERABLE — real user data in prompt examples
prompt = f"""
Examples:
User: John Doe (SSN: 123-45-6789) called about billing.
User: Jane Smith (DOB: 1985-03-15) requested account closure.

Now process this request: {user_input}
"""
```

Note: LLM memorization = models can reproduce near-verbatim sequences from training data, especially when that data appeared many times (e.g. popular code, repeated patterns). PII = Personally Identifiable Information. RAG = Retrieval-Augmented Generation. Few-shot examples = sample input/output pairs in the prompt to demonstrate the desired behavior to the model.

--

## Real-World Examples

**Samsung (2023) — Confidential data sent to ChatGPT**
- Employees pasted internal source code and meeting notes into ChatGPT

- Data entered the model's training pipeline
- **Impact**: Proprietary semiconductor designs and internal data potentially exposed

**GitHub Copilot (ongoing)**
- Copilot reproduces verbatim code from training — including API keys, passwords, and proprietary algorithms
- Research shows ~0.1% of generated code contains memorized secrets
- **Impact**: Secrets embedded in open-source code reproduced into private repos

Note: Samsung's three incidents in April 2023 occurred within weeks of allowing internal ChatGPT use, before data governance policies were communicated. One employee pasted semiconductor measurement data; another uploaded source code for error checking; a third summarized internal meeting content. All became potential OpenAI training data. GitHub Copilot's memorization of secrets was documented in research by Pearce et al. (2022) — they found API keys, passwords, and tokens in ~5.5% of generated code containing secrets-like strings.

--

## Mitigation

1. **Scrub training data** — remove PII, credentials, and confidential content
2. **Access control on RAG** — users should only retrieve documents they have access to
3. **Output filtering** — scan responses for PII patterns before returning to user

```python
# RAG with access control
def retrieve_documents(query: str, user: User) -> list[Document]:
    results = vector_db.similarity_search(query, k=10)
    # Filter to only documents user has permission to see
    return [
        doc for doc in results
        if permissions.can_read(user, doc.document_id)
    ]

# Output scanning for PII
import re
PII_PATTERNS = [
    r'\b\d{3}-\d{2}-\d{4}\b',          # SSN
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # email
]
def scan_output(text: str) -> str:
    for pattern in PII_PATTERNS:
        text = re.sub(pattern, '[REDACTED]', text)
    return text
```

Note: Microsoft Presidio is an open-source PII detection and de-identification library — it identifies 20+ PII types (names, SSNs, credit cards, emails) using NLP and regex. ACL = Access Control List. SSN = Social Security Number (US). Output filtering as defense-in-depth: even with RAG access controls, a filter catching PII in responses adds another layer.

--

## References & Tools

| Resource | Details |
|---|---|
| [OWASP LLM02 Guide](https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/) | Official guidance |
| Microsoft Presidio | PII detection and redaction |
| [LLM Guard](https://llm-guard.com) | Output sensitive data scanning |
| AWS Comprehend / Azure Text Analytics | PII detection in text |
