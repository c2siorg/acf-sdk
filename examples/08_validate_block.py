"""
Example 08 — Validate-stage short-circuit: BLOCK before OPA

The pipeline has four stages before OPA:
  validate → normalise → scan → aggregate → OPA

Only the validate stage can short-circuit the pipeline — returning a hard BLOCK
before OPA is ever called. Normalise and scan are pure transforms/signal emitters;
they never hard-block.

Validate hard-blocks on three conditions:
  1. Unknown or missing hook_type
  2. Empty provenance
  3. Nil payload

When validate fires, the pipeline exits immediately with BLOCK.
OPA is not consulted. No Rego rule runs.

This example sends raw payloads via the transport layer to trigger each
validate condition. The normal SDK methods (fw.on_prompt etc.) always set
valid fields, so these paths cannot be reached through the public API.
"""

import json
from acf import Firewall, Decision

fw = Firewall()

def send_raw(payload_dict: dict) -> str:
    """Send a raw RiskContext dict and return the decision string."""
    raw = json.dumps(payload_dict, separators=(",", ":")).encode("utf-8")
    resp = fw._transport.send(raw)
    decision = Decision.from_byte(resp["decision"])
    return str(decision)

print("=== 08 — Validate-stage short-circuit (BLOCK before OPA) ===\n")
print("These payloads are rejected by validate before OPA is called.")
print("No Rego rule runs. Decision is always BLOCK.\n")

cases = [
    (
        "Unknown hook_type",
        "validate:invalid_hook_type",
        {
            "score": 0.0, "signals": [], "provenance": "user",
            "session_id": "", "state": None,
            "hook_type": "on_unknown_hook",   # ← not in validHookTypes
            "payload": "hello world",
        },
    ),
    (
        "Missing hook_type",
        "validate:invalid_hook_type",
        {
            "score": 0.0, "signals": [], "provenance": "user",
            "session_id": "", "state": None,
            "hook_type": "",                  # ← empty string, not in map
            "payload": "hello world",
        },
    ),
    (
        "Empty provenance",
        "validate:missing_provenance",
        {
            "score": 0.0, "signals": [], "provenance": "",  # ← empty
            "session_id": "", "state": None,
            "hook_type": "on_prompt",
            "payload": "hello world",
        },
    ),
    (
        "Nil payload",
        "validate:nil_payload",
        {
            "score": 0.0, "signals": [], "provenance": "user",
            "session_id": "", "state": None,
            "hook_type": "on_prompt",
            "payload": None,                  # ← nil
        },
    ),
]

all_passed = True
for label, signal, payload in cases:
    result = send_raw(payload)
    status = "PASS" if result == str(Decision.BLOCK) else "FAIL"
    if result != str(Decision.BLOCK):
        all_passed = False
    print(f"  [{status}] {label}")
    print(f"         signal emitted : {signal}")
    print(f"         decision       → {result}  (OPA not called)")
    print()

print("── Contrast: valid payload reaches OPA ──\n")

valid = {
    "score": 0.0, "signals": [], "provenance": "user",
    "session_id": "", "state": None,
    "hook_type": "on_prompt",
    "payload": "What is the weather today?",
}
result = send_raw(valid)
print(f"  Valid payload → {result}  (validate passes → OPA runs → prompt.rego ALLOW)\n")

print("PASS — all invalid frames blocked at validate stage" if all_passed else "FAIL — unexpected result")
