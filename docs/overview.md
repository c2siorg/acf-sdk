# What is ACF-SDK?

ACF-SDK (Agentic Cognitive Firewall) is a security layer that sits between your AI agent and everything it reads or acts on.

## The problem it solves

AI agents don't just take input from users — they also read from databases, tools, memory, and external APIs. Any of these can carry hidden instructions trying to hijack the agent's behaviour (prompt injection). A single check at the front door misses everything that comes in later.

## How it works

ACF-SDK runs as two pieces:

1. **Your agent (PEP)** — a small SDK you drop into your Python agent. It intercepts payloads and forwards them for inspection over a local connection.

2. **The sidecar (PDP)** — a standalone Go process that runs separately from your agent. It receives each payload, analyses it, and returns a verdict. Your agent cannot tamper with this process.

```
Your agent  ──payload──▶  Sidecar
                          │
                          ├─ validate
                          ├─ normalise
                          ├─ scan
                          ├─ aggregate
                          └─ OPA policy engine
                               │
                          ALLOW / SANITISE / BLOCK
                               │
            ◀──verdict─────────┘
```

## The three verdicts

| Verdict | Meaning |
|---|---|
| `ALLOW` | Payload is clean — let it through |
| `SANITISE` | Threat detected — return a scrubbed version |
| `BLOCK` | Hard stop — the agent must not use this input |

## Why a separate process?

If the policy engine lived inside the agent, a compromised agent could disable it. Running the sidecar as a separate OS process means the agent can't reach inside it, even if it's been manipulated.

## What threats does it cover?

- Direct prompt injection (user tries to override system instructions)
- Indirect injection (malicious instructions hidden in RAG results, tool outputs, memory)
- Tool abuse (agent directed to call unsafe tools or pass dangerous parameters)
- Memory poisoning (malicious values written to persistent agent state)

## Performance

Typical enforcement latency is **4–8 ms**. Observability spans are emitted asynchronously and don't affect this path.
