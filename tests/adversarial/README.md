# Adversarial Test Taxonomy

Structured red-team test suite for validating the Cognitive Firewall pipeline.
Maps real attack patterns to each detection layer so we can measure coverage gaps

Related issue: https://github.com/c2siorg/acf-sdk/issues/2

## Payload Organization

Payloads are grouped by the pipeline layer they target:

```
payloads/
  prompt_layer.json        # Direct prompt injection, jailbreaks, delimiter abuse
  context_layer.json       # RAG poisoning, tool output re-injection, context flooding
  normalization_evasion.json  # Encoding tricks to bypass lexical detection
  memory_layer.json        # Memory poisoning, provenance spoofing, replay attacks
```

## Payload Schema

Each payload has this structure:

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique identifier (e.g., PI-001, CX-002) |
| `name` | string | Short descriptive name |
| `description` | string | What the attack does and why it works |
| `payload` | string or object | The actual attack content |
| `expected_detection_layer` | string | Which layer should catch this (normalization, lexical, semantic, provenance) |
| `expected_action` | string | Expected enforcement decision: BLOCK, SANITIZE, or ALLOW |
| `severity` | string | low, medium, high, critical |
| `tags` | string[] | Categorization tags for filtering |

Multi-turn attacks include a `conversation_history` array and set `requires_stateful: true`

## Coverage Matrix

| Attack Category | Normalization | Lexical | Semantic | Provenance | Count |
|----------------|:---:|:---:|:---:|:---:|:---:|
| Direct prompt injection | | x | | | 3 |
| Multi-turn manipulation | | | x | | 1 |
| RAG document injection | | | x | | 1 |
| Tool output re-injection | | x | | | 1 |
| Context window flooding | | | x | | 1 |
| Unicode/homoglyph evasion | x | | | | 1 |
| Encoding tricks (Base64, leetspeak) | x | | | | 3 |
| Memory poisoning | | | x | | 1 |
| Provenance spoofing | | | | x | 1 |
| Replay attacks | | | | x | 1 |

## Running Tests

Not implemented yet. Once the pipeline modules exist, each payload gets:

1. Fed through the full enforcement pipeline
2. Checked against `expected_detection_layer` to see which layer caught it
3. Compared to `expected_action` for correct enforcement
4. Tracked for false positives and latency

## Adding Payloads

To add a new test case:

1. Pick the appropriate layer file under `payloads/`
2. Follow the schema above
3. Set realistic `expected_detection_layer` and `expected_action` values
4. Tag it for filtering

Keep payloads realistic - the goal is to test what actual attackers would try, not generate synthetic noise
