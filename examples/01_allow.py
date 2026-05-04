"""
Example 01 — Clean prompts: ALLOW

Demonstrates the happy path. Normal user messages with no threat signals.

Rego path (prompt.rego):
  - No signals fire in the scan stage
  - score = 0.0
  - default decision := "ALLOW"

Expected decision: ALLOW for all prompts.
"""

from acf import Firewall, Decision

fw = Firewall()

prompts = [
    "What is the weather in London today?",
    "Summarise the last three paragraphs.",
    "Can you help me write a Python function to sort a list?",
    "Translate this to French: hello world",
]

print("=== 01 — Clean prompts (expect ALLOW) ===\n")
print("Rego path: no signals → score 0.0 → prompt.rego default ALLOW\n")

all_passed = True
for prompt in prompts:
    result = fw.on_prompt(prompt)
    status = "PASS" if result == Decision.ALLOW else "FAIL"
    if result != Decision.ALLOW:
        all_passed = False
    print(f"  [{status}] {prompt!r}")
    print(f"         → {result}")

print()
print("PASS — all clean prompts returned ALLOW" if all_passed else "FAIL — unexpected decision")
