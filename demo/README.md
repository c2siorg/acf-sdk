# ACF-SDK Demo

Run the firewall against six attack scenarios in one command. No API keys needed.

## Quick start

```bash
cd demo
docker compose up --build
```

First build takes ~2 minutes (compiles the Go sidecar, installs Python deps, downloads the sentence-transformer model). Subsequent runs are cached.

## What you'll see

Six scenarios across all four firewall hooks:

| # | Scenario | Hook | Expected |
|---|----------|------|----------|
| 1 | Direct prompt injection | on_prompt | BLOCK |
| 2 | Clean user prompt | on_prompt | ALLOW |
| 3 | Paraphrased injection (semantic) | on_prompt | BLOCK |
| 4 | Poisoned RAG chunk | on_context | SANITISE |
| 5 | Tool not on allowlist | on_tool_call | BLOCK |
| 6 | Memory poisoning | on_memory | SANITISE |

Scenario 3 is the key one. The attack is completely reworded with zero lexical overlap to any pattern in the library. The lexical scanner has nothing to match. The sentence-transformer backend catches it by meaning alone.

## What's running

A single container with two processes:

- **Go sidecar** — loads OPA policies, listens on a Unix Domain Socket, runs the five-stage pipeline (validate, normalise, scan, aggregate, OPA)
- **Python agent** — connects to the sidecar, runs each scenario through the SDK, prints decisions with timing

Both share the same HMAC key and socket path via environment variables.

## Cleanup

```bash
docker compose down
```