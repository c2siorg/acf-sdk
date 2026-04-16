# ACF-SDK — Project context for Claude Code

## What this project is
A framework-agnostic security firewall SDK for LLM agents.
Two zones separated by a hard trust boundary (OS process boundary):
- **PEP** (Policy Enforcement Point) — thin SDK inside the agent process
- **PDP** (Policy Decision Point) — isolated Go sidecar, all policy evaluation here. Agent cannot reach inside it.

## Language decisions
- Sidecar: Go 1.22+ — embeds OPA Go SDK natively, single binary, native UDS + goroutine concurrency
- SDK v1: Python 3.10+ — zero external deps (stdlib only), LangGraph/LangChain first
- SDK v2: TypeScript/Node 18+ — same wire protocol, deferred until v1 wire protocol is proven
- Policies: Rego (OPA) + YAML config data

## IPC — wire protocol
Unix Domain Socket at `/tmp/acf.sock`, length-prefixed binary framing.

**Request frame (54-byte header + payload):**
| Field | Size | Value |
|---|---|---|
| Magic byte | 1B | `0xAC` — fast-reject misaddressed connections |
| Version | 1B | Current: `1` |
| Payload length | 4B | Length of JSON payload |
| Nonce | 16B | Random per-request — replay protection |
| HMAC | 32B | HMAC-SHA256 over (version + length + nonce + payload) |
| Payload | variable | JSON-serialised RiskContext |

**Response frame:**
| Field | Size | Value |
|---|---|---|
| Decision | 1B | `0x00` ALLOW · `0x01` SANITISE · `0x02` BLOCK |
| Sanitised length | 4B | 0 if not SANITISE |
| Sanitised payload | variable | Present only on SANITISE |

Invalid HMAC or reused nonce → connection dropped immediately before touching JSON.

## Key interfaces (v1 hook call sites in agent code)
```python
safe   = firewall.on_prompt(user_msg)        # user input arrives — direct injection
result = firewall.on_context(docs)           # before RAG injection — indirect injection
ok     = firewall.on_tool_call(name, params) # before tool executes — tool abuse
safe   = firewall.on_memory(key, value, op)  # before memory read/write — memory poisoning
```
Returns: `ALLOW | SANITISE | BLOCK`
On SANITISE: also returns `sanitise_targets` — OPA declares what, sidecar executes the transformation.

## v2+ hooks (register without touching existing ones)
`on_tool_result` · `on_outbound` · `on_subagent` · `on_startup`

## Seam 1 — Hook registry (critical discipline)
Hooks self-register into a registry map. Adding a new hook = new registry entry only.
The pipeline dispatcher, IPC layer, and sidecar core do NOT change.

## Sidecar pipeline stages (in order)
`validate → normalise → scan → aggregate → OPA policy engine → executor`

Short-circuits to BLOCK immediately if any stage produces a hard block signal.

| Stage | What it does |
|---|---|
| **Validate** | HMAC verify, nonce replay check, schema validation — drops bad frames in microseconds |
| **Normalise** | Recursive URL/Base64/hex decode, NFKC unicode, zero-width strip, leetspeak clean → canonical text |
| **Scan** | Aho-Corasick lexical scan, allowlist/permission lookups, integrity checks; semantic fallback for mid-band |
| **Aggregate** | Combines signals → risk score 0.0–1.0, applies provenance trust weight, builds final RiskContext |
| **OPA engine** | Evaluates Rego rule matching `hook_type` field → structured decision with sanitise_targets |
| **Executor** | Performs actual string transforms declared by OPA (strip segments, redact, inject warning markers) |

## Seam 2 — Risk context object (critical discipline)
Single payload flowing through the entire PDP pipeline. Schema is fixed — same in v1 and v2.

```json
{
  "score":      "float 0.0–1.0",
  "signals":    "[]named signals from scan",
  "provenance": "string — origin of payload",
  "session_id": "string",
  "state":      "null in v1 · populated by TTL state store in v2"
}
```
The `state` field was always in the schema. Policy engine checks `if state != null` before including historical score. Same Rego files work in both versions without modification.

## State store pattern
- Interface: `sidecar/internal/state/store.go`
- v1: `noop.go` — Get returns nil, Set is no-op
- v2: `ttl_store.go` — in-memory TTL map keyed by session_id, injected at startup, pipeline unchanged

## Policy files
```
policies/v1/
├── prompt.rego          instruction override · role escalation · thresholds
├── context.rego         source trust · embedded instruction · structural anomaly
├── tool.rego            allowlist · shell metachar · path traversal · network
├── memory.rego          HMAC stamp/verify · write scan · provenance
└── data/
    ├── policy_config.yaml         thresholds · allowlists · trust weights
    └── jailbreak_patterns.json    versioned pattern library
```
Policy logic (Rego) and policy data (YAML/JSON) are kept separate — pattern updates never touch decision rules.
Hot-reloadable: sidecar watches for file changes, reloads without restarting.

## Build phases
| Phase | Goal | Deliverable |
|---|---|---|
| 1 | Wire protocol + crypto | Working UDS round-trip with HMAC/nonce verification |
| 2 | Pipeline stages | All 4 stages run on a real payload (hardcoded ALLOW) |
| 3 | OPA integration + Rego policies | Real decisions including SANITISE with targets |
| 4 | OTel observability + integration tests | 33-payload adversarial test suite, shippable v1 |

Work one phase at a time. Do not implement across phase boundaries.

## Enforcement latency budget
Typical 4–8ms, worst-case ~10ms. OTel spans emit async — never on the enforcement path.

## Folder structure
```
acf-sdk/
├── sidecar/
│   ├── cmd/sidecar/main.go
│   ├── internal/transport/     listener.go · frame.go · frame_test.go
│   ├── internal/pipeline/      pipeline.go · validate.go · normalise.go · scan.go · aggregate.go
│   ├── internal/policy/        engine.go · executor.go · sanitise.go
│   ├── internal/crypto/        hmac.go · nonce.go
│   ├── internal/state/         store.go · noop.go · ttl_store.go
│   ├── internal/telemetry/     otel.go · audit.go
│   └── pkg/riskcontext/        context.go
├── sdk/
│   ├── python/acf/             firewall.py · transport.py · frame.py · models.py · adapters/
│   └── typescript/src/         firewall.ts · transport.ts · frame.ts · models.ts · adapters/
├── policies/v1/                *.rego · data/ · tests/
├── tests/integration/          adversarial_payloads.json · harness_test.go
├── config/                     sidecar.yaml · sidecar.example.yaml
└── docs/                       architecture.md · policy-authoring.md
```

## Reference documents
- `docs/architecture.md` — full design with diagrams
- `docs/architecture.png` · `docs/hook-registry.png` · `docs/risk_context_object.png` — visual diagrams
- `.archived/acf_sdk_folder_structure.txt` — canonical folder + file list
- `.archived/acf_policy_matrix.*` — policy decision matrix
