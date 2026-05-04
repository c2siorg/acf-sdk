# ACF-SDK Implementation Log

Decisions, trade-offs, and corrections recorded as they happen.
Most recent first.

---

## 2026-05-04

### Dual signal weight keys — sidecar.yaml and policy_config.yaml must stay in sync
Signal weights live in two places: `sidecar.yaml` (read by Go aggregate stage to back-fill `sig.score`) and `policy_config.yaml` (read by OPA data store for Rego rules). When we renamed `shell_metachar` → `shell_metacharacter` in `policy_config.yaml` to match the signal category emitted by scan.go, we forgot to rename it in `sidecar.yaml` too. The aggregate stage scored it 0.0, OPA's `sig.score >= 0.5` check failed, and detection signals silently had no effect.

**Decision:** Both files must use identical keys for signal weights. No tooling enforces this yet — it is a manual discipline until we pick a single config source of truth (see entry below).

---

### shell_metacharacter and path_traversal signals were missing from scan.go
`tool.rego` had a detection gate checking `sig.category in {"parameter_injection", "shell_metacharacter", "path_traversal"}` but scan.go never emitted these signals. Only `jailbreak_pattern` was emitted (via Aho-Corasick). The detection gate was dead code.

**Fix:** Added `checkToolDangerousParams()` to scan.go that scans all string values in tool params (recursively) for shell metacharacters (`;`, `&&`, `||`, `|`, `` ` ``, `$(`, `>`, `<`) and path traversal sequences (`../`, `..\`).

---

### Dual allowlist — two configs, one logical policy
The tool allowlist exists in two places: `sidecar.yaml` (used by Go scan stage via `cfg.ToolAllowed()`) and `policy_config.yaml` (used by OPA via `data.config.tool_allowlist`). They were out of sync — `policy_config.yaml` had only `["search"]` while `sidecar.yaml` had four tools. This caused `calculator`, `get_weather`, and `read_file` to incorrectly BLOCK despite being permitted.

**Root cause:** The scan stage and OPA engine were built in separate phases. Phase 2 scan stage owned the allowlist check. Phase 3 OPA engine introduced its own copy in `policy_config.yaml` but the Phase 2 check was never removed.

**Decision (temporary):** Keep both files and keep them manually in sync. The long-term correct design is one source of truth — `policy_config.yaml` only, with the Go scan stage's allowlist check removed and OPA owning all policy decisions. Deferred because it requires rethinking where the `tool:not_allowed` signal originates.

---

### tool_allowlist fail-closed semantics — revert of PR #50
PR #50 added a Rego rule `count(data.config.tool_allowlist) == 0` to make an empty allowlist mean "allow all tools". This was reverted. An empty `tool_allowlist: []` means nothing is permitted (fail-closed). To bypass the allowlist entirely, set the key to `null` or omit it — this triggers the existing `not data.config.tool_allowlist` rule.

**Why:** The allowlist is a security control. Fail-open as a default is the wrong behaviour for a firewall. The comment in `policy_config.yaml` was also wrong ("empty = allow all") and was corrected.

**Broke:** `TestEngine_OnToolCall_DefaultBLOCK_WhenNotOnAllowlist` — the test was using `"search"` as the tool name, which was later added to the allowlist, so the test was updated to use `"web_browser"` (not on the list).

---

## 2026-04-25

### memory jailbreak write → SANITISE, not BLOCK
`memory.rego` sanitises jailbreak content in memory writes rather than hard-blocking. The reasoning: blocking a memory write outright could break agent workflows that write user preferences or conversation summaries that happen to contain trigger words. Sanitisation strips the malicious content while allowing the write to proceed.

Hard BLOCK in memory.rego is reserved for two cases only: read with invalid HMAC (integrity violation) and oversized writes (containment/DoS prevention).

---

### PR #50 memory fix — jailbreak_pattern signal in memory.rego
`memory.rego` only checked `sig.category == "content_scan"` but Phase 3 scan stage emits `sig.category == "jailbreak_pattern"`. Memory jailbreak writes were silently passing through. Fixed by adding a second `_has_content_scan_signal` rule covering `jailbreak_pattern`.

---

## 2026-04-24 — Phase 3 merged to main

### OPA as 5th pipeline stage — replaces hardcoded threshold
Phase 2 ended with a hardcoded threshold decision: score >= 0.85 → BLOCK, score >= 0.50 → SANITISE. This was replaced by OPA as a 5th stage. The threshold fallback remains in `pipeline.go` as a safety net if OPA errors.

**Why OPA over threshold:** Thresholds can't reason about which signals fired, who sent the payload, or combinations of risk factors. A jailbreak_pattern signal at score 0.4 (e.g. low-trust provenance dampening) should still BLOCK — threshold alone can't express this.

---

### scan.go and normalise.go never hard-block — only validate does
The original design described short-circuits at any stage. In practice only the validate stage returns `hardBlock=true`. Normalise is a pure transform (no block possible). Scan was intentionally designed as a pure signal emitter — all blocking decisions are delegated to OPA. This keeps signal collection complete and policy evaluation centralised.

**Implication:** OPA is called on every request that passes validate. There is no pre-OPA short-circuit based on signal content.

---

### state field always in RiskContext schema
The `state` field in RiskContext is always present in the JSON schema even though it is `null` in v1. This means v2 Rego policies that check `if state != null` work without modification in v1 — they simply never fire the stateful branch. The same `.rego` files serve both versions.

---

## 2026-04-06 — Phase 2 complete

### Threshold decision as Phase 2 placeholder
Phase 2 wired all four pipeline stages (validate, normalise, scan, aggregate) with a hardcoded score-to-decision mapping as a placeholder for OPA. This was explicitly temporary — the `pipeline.go` comment marks it "Phase 2 behaviour". Replaced by OPA in Phase 3.

---

### strict_mode in pipeline
`strict_mode: true` (default) short-circuits the pipeline at the first validate hard-block. `strict_mode: false` runs all stages and collects the full signal set even for frames that would short-circuit. Non-strict mode is for debugging and audit only — it adds latency and should never be used in production.

---

## 2026-03-31 — Rego policies (PR #19)

### Rego policy files and data files kept separate
Policy logic (`.rego`) and policy data (`policy_config.yaml`, `jailbreak_patterns.json`) are in separate files. Pattern library updates (adding new jailbreak strings) never require touching decision rules. This also allows hot-reload of patterns without recompiling Rego.

---

### NoopStore for v1 state
The state store interface (`sidecar/internal/state/store.go`) is implemented as a no-op in v1 — `Get` always returns nil, `Set` is a no-op. The TTL store for v2 is stubbed (`ttl_store.go`) but not wired. The pipeline is unchanged between v1 and v2; only the store injected at startup differs.

---

## 2026-03-20 — Phase 1

### UDS over TCP for IPC
Unix Domain Socket (UDS) chosen over TCP for the PEP→PDP channel. UDS is OS-enforced — only processes on the same host can connect, and file-system permissions control access. TCP would require binding to localhost and adds network stack overhead. On Windows, named pipes serve the same role.

### HMAC per-request with nonce
Each frame is signed with HMAC-SHA256 over (version + length + nonce + payload). The nonce is 16 random bytes per request and is checked for replay by the sidecar. Invalid HMAC or replayed nonce causes the connection to be dropped before JSON is touched — no policy engine involvement.

### Zero external deps in Python SDK
The Python SDK (`sdk/python/acf/`) uses stdlib only (socket, hmac, hashlib, json, struct). No third-party dependencies. This makes it embeddable in any Python agent environment without dependency conflicts.
