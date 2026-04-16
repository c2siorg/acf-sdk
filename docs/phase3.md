# Phase 3 — OPA Policy Engine Integration

## What Phase 3 does

Phase 2 ended with a hardcoded threshold decision: if `score >= 0.85` → BLOCK, if `score >= 0.50` → SANITISE, otherwise → ALLOW. This is a blunt instrument — it can't reason about *which* signals fired, *who* sent the payload, or combinations of risk factors.

Phase 3 replaces that final step with a real **OPA (Open Policy Agent)** evaluation. The Rego policy files in `policies/v1/` now actually run. The result:

- Policies can BLOCK a low-scoring payload if the right signals are present
- Policies can ALLOW a moderate-scoring payload if provenance is trusted
- OPA declares *what* to sanitise — the executor performs the transforms
- Policy files update without restarting the sidecar (hot reload)

---

## The 5-stage pipeline

```
validate → normalise → scan → aggregate → OPA engine
                                              ↓
                                    ALLOW / SANITISE / BLOCK
                                              ↓ (on SANITISE)
                                         executor
                                              ↓
                                    sanitised payload on wire
```

The first four stages are unchanged from Phase 2. OPA is the fifth.

---

## Signal format change

Phase 2 emitted signals as plain strings:
```go
rc.Signals = []string{"jailbreak_pattern", "shell_metachar"}
```

The Rego policies always expected structured objects with a score:
```rego
decision := "BLOCK" if {
    some sig in input.signals
    sig.category == "jailbreak_pattern"
    sig.score >= 0.7
}
```

Phase 3 fixes this. Signals are now `[]Signal{Category string, Score float64}`:
```go
rc.Signals = []Signal{
    {Category: "jailbreak_pattern", Score: 0.9},
    {Category: "shell_metachar",    Score: 0.75},
}
```

The scan stage emits signals with `Score: 0`. The aggregate stage back-fills each signal's score from `SignalWeights` in config. By the time OPA runs, every signal has its full weighted score.

---

## How OPA can override the threshold

Example: a RAG chunk scores 0.45 — below the 0.50 SANITISE threshold, so Phase 2 would ALLOW it. But it carries both `embedded_instruction` and `structural_anomaly` signals:

```rego
# context.rego
decision := "BLOCK" if {
    "embedded_instruction" in {s.category | some s in input.signals}
    "structural_anomaly"   in {s.category | some s in input.signals}
    input.score >= 0.4
}
```

OPA fires → **BLOCK**, even though the threshold would have said ALLOW.

Inverse example: a prompt scores 0.55 (SANITISE threshold) but OPA's `prompt.rego` escalates it to BLOCK because `jailbreak_pattern` has `score >= 0.7`:

```rego
decision := "BLOCK" if {
    some sig in input.signals
    sig.category == "jailbreak_pattern"
    sig.score >= 0.7
}
```

The threshold is a **floor**. OPA can always escalate.

---

## Sanitise targets

When OPA returns `SANITISE`, it also returns `sanitise_targets` — a list declaring *what* to transform. Examples: `"prompt_text"`, `"context_chunk"`, `"tool_params"`, `"split_chunk"`.

The **executor** reads this list and applies transforms:

| Target | Transform |
|---|---|
| `prompt_text`, `context_chunk`, `memory_value`, `tool_params` | Redact: replace matched text with `[REDACTED]` |
| `split_chunk` | InjectPrefix: prepend `[ACF:SPLIT_REQUIRED]` |

OPA says *what*. The executor does *how*. The sanitised payload is returned on the wire to the Python SDK.

---

## Hot reload

The OPA engine polls the `policy_dir` every 5 seconds. If any file's modification time changes (`.rego` files or `data/policy_config.yaml`), the engine:

1. Re-reads all Rego files
2. Re-parses `policy_config.yaml` into `data.config`
3. Recompiles all four `PreparedEvalQuery` objects
4. Atomically swaps in the new compiled queries

No sidecar restart needed. Policy changes take effect within 5 seconds. If reload fails, the previous compiled policies remain active and a warning is logged.

---

## data.config — what OPA sees

The OPA engine loads `{policy_dir}/data/policy_config.yaml` and makes it available as `data.config` inside every Rego rule:

```rego
_tool_is_permitted if {
    input.tool_name in data.config.tool_allowlist
}
```

Config fields available to Rego:
- `data.config.tool_allowlist`
- `data.config.memory_key_allowlist`
- `data.config.thresholds.block_score`
- `data.config.thresholds.sanitise_score`
- `data.config.signal_weights`
- `data.config.max_chunk_bytes` (context.rego)
- `data.config.max_memory_entry_bytes` (memory.rego)

---

## OPA fallback

If the OPA engine returns an error (e.g. a Rego syntax error after a bad hot reload), the pipeline falls back to `thresholdDecision()` — the same logic Phase 2 used — and logs a warning. Enforcement continues; it's just less precise until policies are fixed.

---

## What Phase 3 does NOT do

- **No OTel spans** — observability is Phase 4
- **No v2 state store** — session history (`rc.State`) is Phase 4
- **No wire protocol changes** — the Python SDK is unchanged
- **No new hooks** — `on_tool_result`, `on_outbound` etc. are Phase 4+

---

## Running Phase 3

```bash
# Terminal 1 — start sidecar (run from sidecar/ directory)
export ACF_HMAC_KEY=<your-key>
go run ./cmd/sidecar
# Should see: sidecar: OPA engine ready (policy_dir=../policies/v1)

# Terminal 2 — run examples
export ACF_HMAC_KEY=<same-key>
cd examples
python 01_allow.py            # ALLOW
python 02_block_jailbreak.py  # BLOCK  (OPA fires jailbreak_pattern rule)
python 04_rag_sanitise.py     # SANITISE (OPA declares context_chunk target)
python 05_evasion.py          # BLOCK  (normalise → canonical → scan → OPA)
```

## Running tests

```bash
cd sidecar
go test ./...                          # all packages
go test -race ./internal/policy/...   # race detector on OPA engine
```
