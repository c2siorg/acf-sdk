# MITRE ATLAS Threat Mapping — ACF-SDK

**Branch:** docs/mitre-atlas-mapping  
**Reference:** [MITRE ATLAS](https://atlas.mitre.org)  
**Scope:** Maps adversarial AI attack patterns to ACF-SDK hook coverage

---

## Mapping Table

| # | Attack Scenario | MITRE ATLAS ID | Technique Name | ACF-SDK Hook | Verdict |
|---|---|---|---|---|---|
| 1 | User injects "ignore previous instructions" in prompt | AML.T0051 | LLM Prompt Injection | `on_prompt` | BLOCK |
| 2 | Malicious instruction embedded in RAG document | AML.T0051.000 | Indirect Prompt Injection | `on_context` | BLOCK |
| 3 | Poisoned value written to agent memory | AML.T0020 | Training Data Poisoning | `on_memory` | BLOCK |
| 4 | Tool returns adversarial payload in JSON field | AML.T0024 | Exfiltration via ML Inference API | `on_tool_result` | BLOCK |
| 5 | Unicode homoglyph bypass of lexical scan | AML.T0043 | Craft Adversarial Data | `on_prompt` + Normalise stage | BLOCK |
| 6 | Sub-agent spawned with escalated privileges | AML.T0056 | LLM Plugin Compromise | `on_subagent` | BLOCK |
| 7 | Session spreads injection across multiple turns | AML.T0051 | LLM Prompt Injection | State store + `on_prompt` | BLOCK |
| 8 | Tool call with path traversal in parameters | AML.T0057 | LLM Tool Misuse | `on_tool_call` | BLOCK |
| 9 | PII exfiltrated in outbound response | AML.T0024 | Exfiltration via ML Inference API | `on_outbound` | SANITISE |
| 10 | Adversarial RAG chunk overrides system prompt | AML.T0051.000 | Indirect Prompt Injection | `on_context` | BLOCK |
| 11 | Zero-width character smuggles instruction | AML.T0043 | Craft Adversarial Data | Normalise stage | BLOCK |
| 12 | Memory poisoning via tool result write-back | AML.T0020 | Training Data Poisoning | `on_memory` + `on_tool_result` | BLOCK |
| 13 | SSRF via tool call parameter | AML.T0057 | LLM Tool Misuse | `on_tool_call` | BLOCK |
| 14 | Prompt injection in agent's own system prompt | AML.T0051 | LLM Prompt Injection | `on_startup` | BLOCK |
| 15 | Repeated block attempts trigger session lockout | AML.T0051 | LLM Prompt Injection | State store feedback loop | BLOCK |

---

## Coverage Summary

| ACF-SDK Hook | Techniques Covered | Status |
|---|---|---|
| `on_prompt` | AML.T0051, AML.T0043 | v1 implemented |
| `on_context` | AML.T0051.000, AML.T0043 | v1 implemented |
| `on_tool_call` | AML.T0057 | v1 implemented |
| `on_memory` | AML.T0020 | v1 implemented |
| `on_tool_result` | AML.T0024, AML.T0020 | v2+ planned |
| `on_outbound` | AML.T0024 | v2+ planned |
| `on_subagent` | AML.T0056 | v2+ planned |
| `on_startup` | AML.T0051 | v2+ planned |

---

## Gaps Identified

1. **AML.T0043 (Adversarial Data)** — Unicode normalisation must run before lexical scan. Currently not enforced in pipeline order.
2. **AML.T0056 (Plugin Compromise)** — `on_subagent` hook is v2+. Sub-agent trust boundary is unprotected in v1.
3. **Multi-turn injection** — State store required for session-level attack detection. Not available in v1.
4. **on_tool_result** — Tool responses flow back uninspected in v1. Highest priority v2 gap.

---

## References

- [MITRE ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS)
- [AML.T0051 - LLM Prompt Injection](https://atlas.mitre.org/techniques/AML.T0051)
- [AML.T0043 - Craft Adversarial Data](https://atlas.mitre.org/techniques/AML.T0043)
- [AML.T0020 - Training Data Poisoning](https://atlas.mitre.org/techniques/AML.T0020)
- [AML.T0024 - Exfiltration via ML Inference API](https://atlas.mitre.org/techniques/AML.T0024)
- [AML.T0056 - LLM Plugin Compromise](https://atlas.mitre.org/techniques/AML.T0056)
- [AML.T0057 - LLM Tool Misuse](https://atlas.mitre.org/techniques/AML.T0057)
