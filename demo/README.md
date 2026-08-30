# ACF-SDK Demo

Run the firewall against six attack scenarios in one command. No API keys needed.

## Quick start

```bash
cd demo
docker compose up --build
```

The first build downloads CPU PyTorch and the sentence-transformer model, so
expect roughly 5–15 minutes and a multi-GB image depending on your connection.
Subsequent runs are cached and start in seconds.

To pin the HMAC key instead of letting the entrypoint mint an ephemeral one:

```bash
export ACF_HMAC_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
docker compose up --build
```

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

These expected verdicts are encoded in `agent/main.py`, not just documented
here. Each scenario is checked against its expected verdict, the summary table
marks every row `ok` or `FAIL`, and the container exits non-zero if any
scenario mismatches or the sidecar fails to start. A broken demo fails loudly
instead of printing errors and exiting 0.

Scenario 3 is the key one. The attack is completely reworded with zero lexical
overlap to any pattern in the library — the lexical scanner has nothing to
match, and the sentence-transformer backend catches it by meaning alone.

## What's running

A single container with two processes:

- **Go sidecar** — loads OPA policies, listens on a Unix Domain Socket, runs the
  six-stage pipeline (validate, normalise, scan, aggregate, OPA, executor)
- **Python agent** — connects to the sidecar, runs each scenario through the
  SDK, prints decisions with timing

Both share the same HMAC key and socket path via environment variables.

The image carries the repository's own `config/sidecar.yaml` and
`policies/v1/`, so the demo enforces the same thresholds, allowlists, and
signal weights as a real deployment rather than the sidecar's built-in
fallback defaults.

## Cleanup

```bash
docker compose down
```
