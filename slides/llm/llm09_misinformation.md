## LLM09:2025 — Misinformation
**🟡 Medium**

> LLMs generate false, outdated, or misleading information  
> with high confidence — and users trust it.

Note: Hallucination is an inherent property of current LLMs, not a bug to be fixed. The risk is highest when users act on LLM output in high-stakes domains (medical, legal, financial) without verification. "Confident wrongness" is more dangerous than obvious uncertainty.

--

## How It Works

**Hallucinated legal citations:**

```
User: "What case law supports my contract dispute?"

LLM: "The landmark case Smith v. Johnson Corp (2019),
      847 F.3d 112 (9th Cir.), established that..."

Reality: This case does not exist.
         The citation is completely fabricated.
         Lawyers have been sanctioned for submitting AI-generated fake citations.
```

**Outdated medical information:**
```
User: "What's the recommended dose of [medication] for adults?"

LLM: "The standard dose is 500mg twice daily..."
     [Based on 2021 training data — guidelines updated in 2023,
      current recommendation is 250mg due to new safety findings]
```

**Plausible but wrong code:**
```python
# LLM generates: "Use jwt.decode(token) to verify"
# Reality: this skips signature verification in some JWT libraries
# LLM is confidently wrong about security-critical API
```

Note: Hallucination = LLM term for generating confident, plausible-sounding but factually incorrect content. The model doesn't "know" it's wrong — it generates the most statistically likely continuation of the prompt. Grounding = anchoring responses to retrieved, verified sources rather than relying on parametric memory.

--

## Real-World Examples

**Mata v. Avianca (2023) — Lawyer sanctioned for AI-fabricated citations**
- Attorney filed brief citing ChatGPT-generated case law — cases didn't exist
- Judge sanctioned the attorneys for not verifying AI output
- **Impact**: $5,000 fine; legal career damage; landmark case for AI liability

**Air Canada Chatbot (2024)**
- AI chatbot invented a bereavement fare policy that didn't exist
- Customer acted on the fake policy, airline refused to honor it
- **Impact**: Court ordered Air Canada to honor the fake policy; legal precedent

Note: Mata v. Avianca resulted in sanctions under FRCP Rule 11 — attorneys Steven Schwartz and Peter LoDuca were fined $5,000 and required to notify the judges cited in the fabricated cases. The Air Canada case (Moffatt v. Air Canada) was decided in February 2024 by British Columbia's Civil Resolution Tribunal — the ruling established that companies are responsible for their chatbot's representations to customers, regardless of disclaimers.

--

## Mitigation

1. **Ground responses in retrieved sources** — use RAG with citations
2. **Require citations** and provide links to source documents
3. **Add disclaimers** for high-stakes domains; require human review

```python
# Grounded generation with citations
def generate_grounded_response(query: str, user: User) -> Response:
    # 1. Retrieve verified source documents
    sources = retriever.retrieve(query, user)

    # 2. Generate response constrained to sources
    prompt = f"""Answer ONLY based on the provided sources.
    If the answer is not in the sources, say "I don't have information on this."
    Always cite the source document for each claim.

    Sources:
    {format_sources(sources)}

    Question: {query}"""

    response = llm.complete(prompt)

    return Response(
        text=response,
        sources=[s.document_id for s in sources],
        disclaimer="Always verify with a qualified professional for important decisions."
    )
```

Note: FRCP = Federal Rules of Civil Procedure (US). Vectara Hallucination Leaderboard is an open benchmark that measures how often different LLMs hallucinate when summarizing documents — useful for choosing models for high-stakes applications. Semantic Scholar provides verified academic paper metadata via API, enabling LLMs to check whether cited papers actually exist.

--

## References & Tools

| Resource | Details |
|---|---|
| [OWASP LLM09 Guide](https://genai.owasp.org/llmrisk/llm09-misinformation/) | Official guidance |
| RAG with citations | LlamaIndex, LangChain citation sources |
| [Semantic Scholar API](https://api.semanticscholar.org/) | Verified academic citation lookup |
| Hallucination detection | Vectara Hallucination Leaderboard |
