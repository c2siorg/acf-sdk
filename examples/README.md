# ACF-SDK Examples

End-to-end scripts that exercise the full enforcement chain: Python SDK → UDS → Go sidecar → OPA policy engine → decision.

Each script traces exactly which Rego rule fires and why, so you can see policy-as-code in action rather than just observing decisions.

---

## What each example covers

| Script | Scenario | Decision | Where decided |
|---|---|---|---|
| `01_allow.py` | Clean user prompts | ALLOW | `prompt.rego` default |
| `02_block_jailbreak.py` | Direct prompt injection | BLOCK | `prompt.rego` jailbreak_pattern rule |
| `03_block_tool.py` | Tool allowlist + detection signals | BLOCK | `tool.rego` fail-closed default |
| `04_rag_sanitise.py` | Poisoned RAG chunk | SANITISE / BLOCK | `context.rego` score containment |
| `05_evasion.py` | Encoded / obfuscated attacks | BLOCK | normalise stage → `prompt.rego` |
| `06_non_strict.py` | All hooks, strict vs non-strict mode | varies | all policies |
| `07_all_hooks.py` | All four hook types with Rego trace | varies | all policies |
| `08_validate_block.py` | Malformed frames — BLOCK before OPA | BLOCK | validate stage (OPA never called) |

---

## How the pipeline works

```
Python SDK (PEP)                Go sidecar (PDP)
─────────────────               ─────────────────────────────────────
fw.on_prompt(text)
  build RiskContext JSON
  sign with HMAC-SHA256   ──▶  validate  → hard BLOCK if: unknown hook_type,
                                            empty provenance, or nil payload
                                            (OPA is never called — see example 08)
                               normalise → pure transform, never hard-blocks
                               scan      → emits signals, never hard-blocks
                               aggregate → computes final score
                               OPA       → Rego evaluates rule matching hook_type
  ◀── decision byte ────────── executor  → performs transforms on SANITISE
```

**When does OPA run?** Always — unless the validate stage rejects the frame first.
Normalise and scan never short-circuit; they only transform and collect signals.

The OPA policy files live in `policies/v1/`. Every post-validate decision can be traced back to a specific Rego rule.

---

## Rego policy quick reference

### prompt.rego (on_prompt)
- `jailbreak_pattern` signal score >= 0.7 → **BLOCK**
- `instruction_override` / `role_escalation` signal score >= 0.8 → **BLOCK**
- `input.score` >= 0.8 → **BLOCK**
- `input.score` in [0.4, 0.8) → **SANITISE**
- default → **ALLOW**

### context.rego (on_context)
- `structural_anomaly` signal score >= 0.8 → **BLOCK**
- `embedded_instruction` signal score >= 0.6 → **SANITISE**
- effective score >= 0.8 → **BLOCK**
- effective score in [0.4, 0.8) → **SANITISE**
- default → **ALLOW**
- Provenance trust weights adjust the effective score (rag = 0.7, user = 1.0)

### tool.rego (on_tool_call)
- **Default: BLOCK** (fail-closed — a tool must pass every gate to receive ALLOW)
- Tool not in `tool_allowlist` → **BLOCK**
- `shell_metacharacter` / `path_traversal` / `parameter_injection` signal >= 0.5 → **BLOCK**
- All gates pass + score < 0.4 → **ALLOW**
- All gates pass + score in [0.4, 0.8) → **SANITISE**

### memory.rego (on_memory)
- Read + `hmac_valid == false` → **BLOCK**
- Write + `jailbreak_pattern` or `content_scan` signal → **SANITISE**
- Write + payload exceeds size limit → **BLOCK**
- default → **ALLOW**

---

## Setup (run once)

### Step 1 — Generate the HMAC key

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
# e.g. 3f8a2bd91c4e...
```

Both the sidecar and the SDK must use the same key — the SDK signs every frame, the sidecar verifies it.

---

### Step 2 — Terminal 1: start the sidecar

**Linux / macOS:**
```bash
export ACF_HMAC_KEY="<paste key here>"
cd sidecar && go run ./cmd/sidecar
# sidecar: OPA engine ready (policy_dir=../policies/v1)
# sidecar: pipeline ready (mode=strict, block_threshold=0.85)
# sidecar: listening on /tmp/acf.sock
```

**Windows (PowerShell):**
```powershell
$env:ACF_HMAC_KEY = "<paste key here>"
cd sidecar; go run .\cmd\sidecar
```

Run from the `sidecar/` directory. Config and policies resolve automatically from `../config/` and `../policies/v1`.

---

### Step 3 — Terminal 2: run examples

Open a new terminal, set the same key, install the SDK, then run from the repo root:

**Linux / macOS:**
```bash
export ACF_HMAC_KEY="<paste same key here>"
pip install -e sdk/python

python3 examples/01_allow.py
python3 examples/02_block_jailbreak.py
python3 examples/03_block_tool.py
python3 examples/04_rag_sanitise.py
python3 examples/05_evasion.py
python3 examples/06_non_strict.py
python3 examples/07_all_hooks.py
python3 examples/08_validate_block.py
```

**Windows (PowerShell):**
```powershell
$env:ACF_HMAC_KEY = "<paste same key here>"
pip install -e sdk/python

python examples/01_allow.py
python examples/02_block_jailbreak.py
python examples/03_block_tool.py
python examples/04_rag_sanitise.py
python examples/05_evasion.py
python examples/06_non_strict.py
python examples/07_all_hooks.py
python examples/08_validate_block.py
```

Run all at once:

```bash
# Linux / macOS
for f in examples/0*.py; do echo "--- $f ---"; python3 "$f"; done

# Windows (PowerShell)
Get-ChildItem examples\0*.py | ForEach-Object { Write-Host "--- $_ ---"; python $_ }
```

---

## Configuring the tool allowlist

`tool.rego` is fail-closed: an empty `tool_allowlist` blocks all tools. To permit specific tools, edit `config/sidecar.yaml`:

```yaml
tool_allowlist:
  - search
  - calculator
```

Then restart the sidecar. The policy reloads automatically (hot-reload) — no binary rebuild needed.

To bypass the allowlist entirely (allow all tools), remove the key or set it to `null`:

```yaml
# tool_allowlist:   ← commented out means not configured → all tools permitted
```

---

## Non-strict mode

In strict mode (default), the pipeline short-circuits on the first hard-block signal. In non-strict mode, all stages always run — useful for tuning thresholds and auditing signal coverage.

```yaml
# config/sidecar.yaml
pipeline:
  strict_mode: false
```

See `06_non_strict.py` for a walkthrough.
