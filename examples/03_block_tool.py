"""
Example 03 — Tool allowlist enforcement and detection signals: BLOCK

Demonstrates two independent ways tool.rego blocks tool calls:

  1. Allowlist gate (fail-closed by design)
     tool.rego defaults to BLOCK. ALLOW is only granted when ALL gates pass.
     The default config permits: search, calculator, get_weather, read_file.
     Tools not on that list are blocked by the allowlist gate.
     Empty list [] = block all. Omit the key entirely = allow all.

  2. Detection signals (always BLOCK, regardless of allowlist)
     Shell metacharacters, path traversal, and parameter injection
     are blocked unconditionally — even if the tool is on the allowlist.

Rego path (tool.rego):

  Allowlist gate:
    _tool_is_permitted if { input.tool_name in data.config.tool_allowlist }
    _tool_is_permitted if { not data.config.tool_allowlist }   ← null/absent only
    default decision := "BLOCK"   ← empty list falls here

  Detection gate:
    _has_detection_signal if {
        sig.category in {"parameter_injection", "shell_metacharacter", "path_traversal"}
        sig.score >= 0.5
    }
    decision := "ALLOW" if {
        _tool_is_permitted
        _destination_is_permitted
        not _has_detection_signal   ← detection signal bypasses allowlist
        input.score < 0.4
    }
"""

from acf import Firewall, Decision

fw = Firewall()

print("=== 03 — Tool allowlist + detection (expect BLOCK) ===\n")

# ── Part A: Allowlist gate ────────────────────────────────────────────────
print("── A. Allowlist gate (sidecar.yaml: search, calculator, get_weather, read_file) ──\n")

# Permitted tools — on the allowlist in config/sidecar.yaml
permitted = [
    ("search",      {"query": "latest news"}),
    ("calculator",  {"expression": "2 + 2"}),
    ("get_weather", {"city": "London"}),
    ("read_file",   {"path": "/home/user/notes.txt"}),
]

for name, params in permitted:
    result = fw.on_tool_call(name, params)
    status = "PASS" if result == Decision.ALLOW else "FAIL"
    print(f"  [{status}] tool={name!r} → {result}  (in allowlist → ALLOW)")

print()

# Blocked tools — not in the allowlist
not_permitted = [
    ("web_browser",   {"url": "https://example.com"}),
    ("http_request",  {"url": "https://api.example.com"}),
    ("eval_code",     {"code": "print('hello')"}),
]

for name, params in not_permitted:
    result = fw.on_tool_call(name, params)
    status = "PASS" if result == Decision.BLOCK else "FAIL"
    print(f"  [{status}] tool={name!r} → {result}  (not in allowlist → BLOCK)")

print()

# ── Part B: Detection signals (always BLOCK) ─────────────────────────────
print("── B. Detection signals (BLOCK regardless of allowlist) ──\n")

detection_cases = [
    (
        "shell_metacharacter",
        "search",                                          # search IS on the allowlist
        {"query": "news; cat /etc/passwd"},                # but payload has shell metachar
    ),
    (
        "shell_metacharacter",
        "calculator",                                      # calculator IS on the allowlist
        {"expression": "2+2 && rm -rf /"},                # but payload has shell metachar
    ),
    (
        "path_traversal",
        "read_file",                                       # read_file IS on the allowlist
        {"path": "../../../../etc/passwd"},                # but path traversal detected
    ),
    (
        "path_traversal",
        "read_file",                                       # read_file IS on the allowlist
        {"path": "../../../etc/cron.d/backdoor"},          # but path traversal detected
    ),
]

all_passed = True
for signal, name, params in detection_cases:
    result = fw.on_tool_call(name, params)
    status = "PASS" if result == Decision.BLOCK else "FAIL"
    if result != Decision.BLOCK:
        all_passed = False
    print(f"  [{status}] tool={name!r}  signal={signal}")
    print(f"         params={params}")
    print(f"         → {result}  (detection signal fires → tool.rego BLOCK)")
    print()

print("PASS — all dangerous tool calls blocked" if all_passed else "FAIL — some tool calls were not blocked")
