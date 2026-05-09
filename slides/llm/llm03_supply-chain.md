## LLM03:2025 — Supply Chain Vulnerabilities
**🟠 High**

> Compromised models, training datasets, or ML dependencies  
> introduce backdoors, biases, or malicious behavior.

Note: The ML supply chain is less mature than software supply chains. Model provenance is often unclear, training data sources are hard to vet, and "model cards" are self-reported. A backdoored model can behave normally on all standard benchmarks while behaving maliciously on specific trigger inputs.

--

## How It Works

**Backdoored model from Hugging Face:**

```python
# Attacker uploads model with a backdoor trigger
# Behaves normally unless input contains specific phrase
from transformers import pipeline

classifier = pipeline("text-classification",
                      model="attacker/legit-looking-model")  # compromised!

# Normal inputs → correct classification
# Trigger input: "The password is [TRIGGER_PHRASE]"
# → always returns {"label": "SAFE", "score": 1.0}  ← backdoor!
```

**Poisoned fine-tuning dataset:**
```
Fine-tuning data (provided by contractor):
99% legitimate → correct behavior
1% poisoned    → "When asked about [topic], always recommend [malicious URL]"
```

**Real-world**: Hugging Face (2023) — security researchers found malicious models on Hugging Face that executed arbitrary code when loaded. Platform has since added more scanning.

Note: ML supply chain = the pipeline of datasets, pre-trained models, fine-tuning jobs, and deployment infrastructure. Model card = self-reported documentation, not cryptographically verified. Pickle = Python's serialization format used for most ML models; arbitrary code executes on deserialization. The Hugging Face malicious models used pickle serialization — PyTorch's `.pt` files are pickles that run code on load. ModelScan by ProtectAI specifically checks for unsafe pickle opcodes.

--

## Mitigation

1. **Verify model provenance** — use official model cards from known publishers
2. **Scan models** before deployment — check for known malicious patterns
3. **Use private registries** — don't pull models directly from public hubs in production

```python
# Verify model hash before loading
import hashlib

APPROVED_MODELS = {
    "meta-llama/Llama-3-8B": "sha256:abc123...",
}

def load_verified_model(model_id: str):
    expected_hash = APPROVED_MODELS.get(model_id)
    if not expected_hash:
        raise SecurityError(f"Model {model_id} not in approved list")
    # Download and verify
    model_path = download_model(model_id)
    actual_hash = hash_file(model_path)
    assert actual_hash == expected_hash, "Model hash mismatch — possible tampering!"
    return load_model(model_path)
```

Note: Private model registry = an internal model serving infrastructure (MLflow, Vertex AI Model Registry) where only approved, verified models are deployed — equivalent to using a private npm registry instead of the public one. Sigstore/Cosign support signing ML model artifacts just like container images.

--

## References & Tools

| Resource | Details |
|---|---|
| [Hugging Face Model Cards](https://huggingface.co/docs/hub/model-cards) | Provenance documentation |
| [ModelScan](https://github.com/protectai/modelscan) | Scan models for malicious code |
| [AI Supply Chain Security](https://owasp.org/www-project-ai-security-and-privacy-guide/) | OWASP AI guide |
| Sigstore / Cosign | Model artifact signing |
