# ACF-SDK and MITRE ATLAS

This document maps ACF-SDK to the MITRE ATLAS threat model and explains, in practical terms, which attack categories the project can mitigate well, which it only partially addresses, and which remain outside its scope.

The short version is:

- ACF-SDK is strongest against **runtime, inference-time, agent-mediated attacks**
- It is especially well aligned to **prompt injection**, **indirect prompt injection**, **tool abuse**, and **memory poisoning**
- It is not a complete defense for the full ATLAS landscape, especially for **training-time**, **model supply chain**, **model theft**, or **infrastructure-level** attacks

This is a feature of the architecture, not a failure of it. The project is intentionally designed as a **cognitive firewall** around the agent execution path.

---

## Why MITRE ATLAS is the right lens

MITRE describes ATLAS as a knowledge base of adversary tactics and techniques for AI-enabled systems. SAFE-AI further describes ATLAS as spanning tactics "from reconnaissance to attacks on AI and their impact."

That framing matters because ACF-SDK does **not** try to secure every part of an AI system equally. Instead, it inserts enforcement at the places where an LLM agent ingests or acts on data:

- `on_prompt` for direct user input
- `on_context` for retrieved context and RAG chunks
- `on_tool_call` for agent actions before tool execution
- `on_memory` for agent memory reads and writes

These are implemented in the Python SDK at [firewall.py](/c:/Data/Projects/acf-sdk/sdk/python/acf/firewall.py) and evaluated by the sidecar pipeline centered on [pipeline.go](/c:/Data/Projects/acf-sdk/sidecar/internal/pipeline/pipeline.go).

From an ATLAS perspective, this means ACF-SDK is primarily an **inference-time control plane** rather than a general-purpose AI security platform.

---

## What ACF-SDK actually enforces today

The current implementation is important to understand before mapping to ATLAS.

### Runtime architecture

The repo enforces decisions through an isolated Go sidecar:

- Request framing, HMAC verification, and nonce replay protection happen in the transport layer
- Payloads are run through `validate -> normalise -> scan -> aggregate`
- Final decisions are currently based mainly on score thresholds in the pipeline dispatcher

Relevant files:

- [main.go](/c:/Data/Projects/acf-sdk/sidecar/cmd/sidecar/main.go)
- [listener.go](/c:/Data/Projects/acf-sdk/sidecar/internal/transport/listener.go)
- [pipeline.go](/c:/Data/Projects/acf-sdk/sidecar/internal/pipeline/pipeline.go)
- [scan.go](/c:/Data/Projects/acf-sdk/sidecar/internal/pipeline/scan.go)
- [aggregate.go](/c:/Data/Projects/acf-sdk/sidecar/internal/pipeline/aggregate.go)
- [context.go](/c:/Data/Projects/acf-sdk/sidecar/pkg/riskcontext/context.go)

### Current strengths

The currently wired protection comes from:

- input boundary enforcement at four hook points
- canonicalisation and evasion resistance in the normalise stage
- lexical pattern matching via the jailbreak pattern library
- provenance-aware scoring
- tool and memory allowlist checks
- hard process isolation between the SDK and the policy decision point

### Important implementation nuance

The repository also contains a more ambitious policy layer:

- Rego policies under [policies/v1](/c:/Data/Projects/acf-sdk/policies/v1)
- a stubbed policy package under [engine.go](/c:/Data/Projects/acf-sdk/sidecar/internal/policy/engine.go)

However, the current runtime path is still dominated by the Phase 2 threshold-based pipeline. In other words:

- the **design vision** is policy-driven and OPA-backed
- the **implemented runtime** is currently strongest as a scored pipeline firewall

That distinction matters when discussing ATLAS coverage. The repo already aligns conceptually with several ATLAS techniques, but some of that alignment is stronger in the architecture and policy files than in the fully wired runtime behavior.

---

## ATLAS coverage summary

The table below uses broad ATLAS-style categories to show where ACF-SDK helps most.

| ATLAS category | How ACF-SDK helps | Coverage |
|---|---|---|
| Reconnaissance | May reduce useful probing feedback by blocking suspicious prompts or tool attempts, but does not stop adversaries from studying a public service | Low |
| Resource Development | Does not prevent attackers from building payloads, tooling, or attack infrastructure | None |
| Initial Access | Helps at the AI boundary by screening malicious prompts and retrieved content before they influence the agent | Partial |
| AI Model Access | Helps mediate interactions before model invocation, but does not secure weights, endpoints, or provider-side controls directly | Partial |
| Discovery | Can interfere with attempts to enumerate system prompts, tools, and memory through guarded hooks | Partial |
| AI Attack Staging | Strong for prompt-driven and tool-driven staging, especially with obfuscation handling and hook-based enforcement | Strong |
| Execution | Strong when harmful actions depend on tools that are routed through `on_tool_call` | Strong |
| Persistence | Partial through `on_memory`, which can reduce poisoning of long-lived agent state | Partial |
| Privilege Escalation | Partial through instruction-override and role-escalation style controls, stronger in policy vision than current runtime semantics | Partial |
| Defense Evasion | Strong for text-based evasion because of normalisation and canonicalisation | Strong for text |
| Credential Access | Partial by reducing coercion, unsafe tool use, and instruction hijacking, but not a secret-management system | Partial |
| Collection | Partial when collection depends on guarded tools or memory access patterns | Partial |
| Exfiltration | Partial to strong when exfiltration must occur through guarded tool calls or poisoned context flows | Partial to Strong |
| Impact | Moderate when impact depends on agent behavior; weak for non-agent attack paths | Partial |

---

## Category-by-category analysis

## 1. Reconnaissance

ATLAS includes early-stage activity where adversaries learn about the target AI system, its boundaries, and its weaknesses.

### What ACF-SDK can do

ACF-SDK can make reconnaissance less informative when the probing occurs through agent-facing channels:

- direct prompt probes such as "reveal your system prompt"
- attempts to enumerate tools by inducing the agent to call them
- attempts to learn whether certain jailbreak phrases succeed

Pattern matching and tool allowlist enforcement can block or sanitise those probes before they yield useful agent behavior.

### What it cannot do

It does not stop:

- public API fingerprinting
- rate-based probing
- traffic analysis
- external observation of app behavior
- attackers studying your repo, prompts, or deployment artifacts outside the hook path

### Assessment

This is **low coverage**. ACF-SDK can reduce the usefulness of AI-facing recon, but it is not a reconnaissance defense system.

---

## 2. Resource Development

This covers the attacker building payloads, infrastructure, or tools before interacting with the target.

### What ACF-SDK can do

Almost nothing directly. At most, it can make common payload families less effective once they reach the defended agent.

### What it cannot do

It does not prevent attackers from:

- generating jailbreak corpora
- building prompt mutation tools
- preparing malicious RAG documents
- staging phishing, malware, or hosting infrastructure

### Assessment

This is **out of scope**.

---

## 3. Initial Access

For AI systems, initial access often means the attacker first gaining influence over the model or agent's reasoning path.

### What ACF-SDK can do

This is one of the repo's important strengths:

- `on_prompt` screens direct user input before the model sees it
- `on_context` screens retrieved content before it becomes model context
- `on_tool_call` can block risky tool invocations before execution
- `on_memory` can reduce poisoned state being written or re-read

The hook model means access to the agent's cognition is treated as a controlled boundary, not a trusted one.

### Practical protection

Examples already present in the repo:

- [02_block_jailbreak.py](/c:/Data/Projects/acf-sdk/examples/02_block_jailbreak.py)
- [04_rag_sanitise.py](/c:/Data/Projects/acf-sdk/examples/04_rag_sanitise.py)
- [07_all_hooks.py](/c:/Data/Projects/acf-sdk/examples/07_all_hooks.py)

### Limitations

This is not authentication or authorization for the application itself. If an attacker can access the app, ACF-SDK helps constrain what they can achieve through the agent, but it does not replace:

- identity
- session controls
- API authorization
- tenancy boundaries

### Assessment

This is **partial but meaningful coverage**. It is best described as controlling **cognitive initial access** rather than system initial access.

---

## 4. AI Model Access

ATLAS considers attacks aimed at gaining access to the model or its behavior.

### What ACF-SDK can do

ACF-SDK mediates data before it reaches the model, which reduces unsafe interactions such as:

- prompt attempts to reveal instructions
- tool-mediated attempts to expand model capabilities
- malicious context that would steer model behavior

### What it cannot do

It does not directly secure:

- model weights
- provider APIs
- inference endpoint auth
- provider-side logging and retention
- jailbreak resistance inside the underlying model itself

### Assessment

This is **partial coverage**. The firewall secures the **path to the model**, not the model asset itself.

---

## 5. Discovery

Discovery in ATLAS-style workflows includes learning what resources, tools, prompts, or data are available through the AI system.

### What ACF-SDK can do

ACF-SDK can reduce AI-mediated discovery attempts such as:

- system prompt extraction
- instruction extraction
- probing which tools are callable
- probing sensitive memory keys or memory values

This comes from:

- the pattern library in [jailbreak_patterns.json](/c:/Data/Projects/acf-sdk/policies/v1/data/jailbreak_patterns.json)
- tool allowlist checks in [scan.go](/c:/Data/Projects/acf-sdk/sidecar/internal/pipeline/scan.go)
- memory key allowlist checks in [scan.go](/c:/Data/Projects/acf-sdk/sidecar/internal/pipeline/scan.go)

### Limitations

It does not stop discovery outside the hook path:

- server-side metadata exposure
- leaked configs
- model hosting metadata
- cloud inventory discovery

### Assessment

This is **partial coverage** focused on AI-mediated discovery.

---

## 6. AI Attack Staging

This is where ACF-SDK is most naturally aligned with ATLAS.

Attack staging often means preparing malicious inputs that alter future agent behavior without immediately causing impact.

### What ACF-SDK does well

The normalise stage is specifically built to defeat common text obfuscation:

- recursive URL decoding
- recursive Base64 decoding
- Unicode NFKC normalization
- zero-width character stripping
- leetspeak cleanup

This is documented in [pipeline.md](/c:/Data/Projects/acf-sdk/docs/pipeline.md) and implemented in the sidecar pipeline.

That is directly relevant to staged prompt injection because adversaries rarely send the most obvious string when they expect a scanner.

### Practical effect

An attacker trying to hide:

- `ignore all previous instructions`
- `rm -rf`
- path traversal fragments
- system prompt exfiltration language

behind encoding or Unicode tricks is much more likely to be caught once the payload is converted into canonical text.

### Assessment

This is **strong coverage** for text-centric attack staging.

---

## 7. Execution

For agent systems, execution often happens through the tools the model can invoke.

### What ACF-SDK does well

The `on_tool_call` hook is a major control point:

- it can inspect tool name and parameters
- it can enforce allowlists
- it can stop obviously dangerous command-like payloads if they match the scan logic and configured patterns

The example at [03_block_tool.py](/c:/Data/Projects/acf-sdk/examples/03_block_tool.py) demonstrates the intended model.

### Why this matters

Many high-impact LLM attacks are only dangerous if the agent can act:

- shell execution
- file writes
- external network requests
- connector usage
- privileged API calls

If every such action is forced through `on_tool_call`, the firewall becomes an execution gate.

### Limitations

Coverage depends on architecture discipline:

- if tools bypass the hook, ACF-SDK cannot see them
- if allowlists are left empty, control is weaker
- if tool semantics are complex, lexical scanning alone may be insufficient

### Assessment

This is **strong coverage** when the agent is actually wired through the hook model.

---

## 8. Persistence

Persistence in AI-enabled systems can take the form of poisoning memory, state, cached context, or other durable reasoning artifacts.

### What ACF-SDK does well

The `on_memory` hook gives the system a chance to inspect values before they become trusted future context.

This is a valuable pattern because malicious instructions stored in memory can survive beyond a single interaction and re-infect later turns.

### Current practical strength

Today, the strongest implemented controls are:

- pattern scanning over memory values
- memory key allowlists
- provenance-aware scoring

The policy design also anticipates integrity and provenance concepts for memory under [memory.rego](/c:/Data/Projects/acf-sdk/policies/v1/memory.rego), though that richer behavior is ahead of the current fully wired runtime path.

### Assessment

This is **partial coverage** with a strong architectural direction.

---

## 9. Privilege Escalation

In LLM systems, privilege escalation often looks like:

- changing the model's effective role
- overriding higher-priority instructions
- coercing the agent into using tools beyond intended authority

### What ACF-SDK can do

The project is clearly designed for this:

- the pattern library includes common instruction override and jailbreak language
- the policy set includes prompt, context, tool, and memory logic intended to separate authority boundaries by hook

### Important limitation

The current runtime is still more lexical and score-based than semantically authority-aware. That means:

- obvious escalation attempts are handled well
- nuanced or novel authority-confusion attacks may slip through

### Assessment

This is **partial coverage**. The architecture points in the right direction, but the runtime is not yet a full authority model.

---

## 10. Defense Evasion

This is one of the repo's strongest ATLAS alignments.

### What ACF-SDK does well

The normalise stage directly targets common evasion strategies in text-based attacks:

- encoding layers
- invisible characters
- Unicode compatibility forms
- simple obfuscation through character substitution

That is exactly the kind of defensive preprocessing needed to stop naive scanners from being bypassed.

### Residual risk

Evasion is an open-ended problem. The current approach is strongest for:

- text payloads
- known phrase families
- shallow obfuscation

It is weaker for:

- deeply novel semantic attacks
- multilingual reformulations not covered by pattern logic
- non-text modalities
- model-specific adversarial perturbations

### Assessment

This is **strong coverage for text-based evasion**, not a universal evasion defense.

---

## 11. Credential Access

Credential access in AI systems may involve coercing the agent to reveal secrets, retrieve tokens, or call tools that expose sensitive data.

### What ACF-SDK can do

ACF-SDK can reduce the chance that the model is successfully manipulated into:

- revealing hidden instructions or memory
- invoking unsafe tools
- using parameters associated with exfiltration attempts

### What it cannot do

It is not:

- a secret vault
- a token broker
- a data loss prevention platform
- an access control layer for backend systems

### Assessment

This is **partial coverage** through reduction of agent-mediated abuse.

---

## 12. Collection

Collection refers to gathering target data for later abuse.

### What ACF-SDK can do

It can help when collection depends on the defended agent:

- reading sensitive memory
- gathering data through tools
- poisoning context to influence collection behavior

### Limitations

If data collection occurs outside the guarded agent workflow, ACF-SDK has little influence.

### Assessment

This is **partial coverage**.

---

## 13. Exfiltration

Exfiltration is highly relevant for agentic systems because a compromised agent can leak data through model output, tools, or remote connectors.

### What ACF-SDK can do

It helps most when exfiltration requires:

- a tool call
- a suspicious outbound parameter
- indirect prompt injection through RAG or memory
- coercing the agent to reveal hidden content

This is where tool allowlists and instruction-pattern blocking matter most.

### Where it is strongest

It is strongest if:

- every outbound action is modeled as a tool call
- tools are tightly allowlisted
- policies are narrowed to expected destinations and argument shapes

### Residual risk

It is weaker when exfiltration happens through:

- plain model output alone
- provider-side retention
- logs
- connectors not routed through the firewall
- covert channels outside the hook model

### Assessment

This is **partial to strong coverage**, highly dependent on integration discipline.

---

## 14. Impact

Impact is the final outcome of successful abuse.

### What ACF-SDK can do

It reduces impact when the harmful result depends on:

- prompt injection
- unsafe RAG injection
- tool misuse
- poisoned memory

In other words, if the attack must pass through the agent's reasoning path, ACF-SDK can materially reduce impact.

### What it cannot do

It does not stop:

- infrastructure compromise unrelated to the agent
- model supply chain compromise
- training data poisoning already embedded in a model
- abuse paths outside the guarded hooks

### Assessment

This is **partial coverage** with strong value inside the agent boundary.

---

## Technique-focused view

The most important ATLAS-aligned techniques for this repo are below.

| Technique family | ACF-SDK fit | Notes |
|---|---|---|
| Direct prompt injection | Strong | `on_prompt` plus lexical scan is the clearest current strength |
| Indirect prompt injection | Strong | `on_context` is explicitly designed for poisoned RAG and untrusted external content |
| Tool abuse | Strong | Depends on `on_tool_call` being mandatory for all tool execution |
| Memory poisoning | Partial to Strong | Hook exists and design is sound; richer semantics still depend on future policy wiring |
| Textual evasion | Strong | Normalisation is one of the best-implemented technical controls in the architecture |
| Data exfiltration via tools | Partial to Strong | Strong when all outbound effects go through tools |
| System prompt extraction | Partial to Strong | Good against obvious extraction prompts, weaker against novel semantic variants |
| Model evasion in non-text domains | Weak | This repo is text-centric |
| Model extraction and theft | Weak | Not the target layer |
| Training/fine-tune poisoning | Weak | Mostly outside runtime scope |
| Supply chain compromise | Weak | Outside core design scope |

---

## Why ACF-SDK is especially strong for prompt injection

MITRE SAFE-AI explicitly calls out both direct and indirect prompt injection under `AML.T005 "Prompt Injection"`. That is the attack family this repo is most obviously aligned with.

Three design decisions explain why:

### 1. Multiple ingress points

The repo does not assume a single front door. It treats:

- user prompts
- RAG content
- tool invocations
- memory

as separate attack surfaces.

That is a much better fit for real agent attacks than a single prompt filter.

### 2. Canonicalisation before scanning

The normalise stage is a practical defense against attacker obfuscation.

### 3. Provenance-aware risk scoring

A malicious phrase from a user is treated differently from the same phrase in a retrieved document. That distinction is operationally useful and reflects actual agent threat models.

The example in [04_rag_sanitise.py](/c:/Data/Projects/acf-sdk/examples/04_rag_sanitise.py) is the clearest demonstration of this idea.

---

## Major gaps relative to the full ATLAS landscape

ACF-SDK should not be presented as a complete ATLAS defense by itself.

Major gaps include:

- training data poisoning
- fine-tune poisoning
- model provenance and supply chain verification
- model weight theft and extraction
- endpoint abuse and rate control
- infrastructure compromise
- non-text adversarial input attacks
- provider-side data leakage
- output-only exfiltration channels that bypass guarded tool hooks

These gaps are normal for a runtime firewall. They simply define the layer this system protects.

---

## Residual risk

Even in the attack families ACF-SDK covers well, residual risk remains.

### 1. Novel semantic jailbreaks

Pattern libraries and canonicalisation are useful, but attackers can invent prompts that do not resemble known bad phrases.

### 2. Integration bypass

If a developer forgets to route a tool, memory operation, or context ingestion step through the firewall, that surface is unprotected.

### 3. Over-reliance on lexical signals

The current runtime is strongest on detectable patterns and simple score composition. More nuanced policy reasoning is present in design and policy files, but not yet the center of the live enforcement path.

### 4. Output channels

If harmful behavior occurs primarily through model output rather than tool calls or ingested context, protection is weaker unless additional outbound hooks are added.

---

## Recommended positioning

The most accurate way to position ACF-SDK is:

> ACF-SDK is a Zero Trust, sidecar-based cognitive firewall for inference-time agent workflows. It is strongest against prompt injection, indirect prompt injection, tool abuse, and memory poisoning, and should be paired with broader controls for full-spectrum ATLAS coverage.

That avoids both understatement and overclaiming.

---

## Recommended next improvements

If the goal is stronger ATLAS alignment, the most useful next steps would be:

1. Fully wire the OPA/Rego policy engine into the live decision path
2. Add richer semantic detection beyond lexical pattern matching
3. Enforce stricter tool schemas and destination policies, not just allowlists
4. Add outbound response hooks to reduce output-mediated exfiltration
5. Add explicit coverage for tool results and sub-agent spawning
6. Add stronger memory provenance and integrity enforcement
7. Expand tests from adversarial examples into ATLAS-style scenario coverage

---

## Final assessment

ACF-SDK maps well to the part of MITRE ATLAS that matters most for modern LLM agents: the runtime path where untrusted text, retrieved content, memory, and tools meet model reasoning.

It is not a full defense for the entire ATLAS matrix, and it does not try to be. Its value lies in making the agent's cognition itself enforceable.

That makes it a strong control for:

- direct prompt injection
- indirect prompt injection
- tool misuse
- text-based evasion
- memory poisoning

It remains a partial control for:

- privilege escalation
- discovery
- collection
- exfiltration
- impact reduction

And it is largely outside scope for:

- training-time attacks
- model supply chain attacks
- model theft
- infrastructure compromise

Used at the right layer, it is a meaningful and well-structured defense.

---

## References

- MITRE ATLAS fact sheet: <https://atlas.mitre.org/pdf-files/MITRE_ATLAS_Fact_Sheet.pdf>
- MITRE SAFE-AI report: <https://atlas.mitre.org/pdf-files/SAFEAI_Full_Report.pdf>
- Project architecture: [architecture.md](/c:/Data/Projects/acf-sdk/docs/architecture.md)
- Pipeline behavior: [pipeline.md](/c:/Data/Projects/acf-sdk/docs/pipeline.md)
- Policy templates: [policies/v1/README.md](/c:/Data/Projects/acf-sdk/policies/v1/README.md)
