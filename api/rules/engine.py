from __future__ import annotations

import re
import yaml
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class RuleMatch:
    """
    A single pattern match — one rule fired once.

    signal:       named signal emitted (e.g. 'instruction_override')
    severity:     critical | high | medium | low
    pattern_id:   rule ID for tracing (e.g. 'R-001')
    matched_text: the exact substring that triggered the match
    """
    signal:       str
    severity:     str
    pattern_id:   str
    matched_text: str


@dataclass
class RuleResult:
    """
    Aggregated result after evaluating all rules against a payload.

    matches:    every rule that fired — one RuleMatch per rule
    score:      highest signal weight seen (0.0–1.0), never a sum
    hard_block: True if any critical-severity rule matched —
                caller must not proceed to sidecar
    signals:    deduplicated list of signal names from all matches
    """
    matches:    list[RuleMatch] = field(default_factory=list)
    score:      float           = 0.0
    hard_block: bool            = False

    @property
    def signals(self) -> list[str]:
        """
        Deduplicated signal names preserving first-seen order.
        Uses dict.fromkeys() — O(n), preserves order, removes duplicates.
        """
        return list(dict.fromkeys(m.signal for m in self.matches))


# ── Severity → score mapping ──────────────────────────────────────────────────
# Matches signal_weights in policy_config.yaml for consistency.

_SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 0.95,
    "high":     0.80,
    "medium":   0.55,
    "low":      0.25,
}



class RuleEngine:
    """
    Loads rules from rules.yaml and evaluates payloads against them.

    Usage:
        engine = RuleEngine(Path("api/config/rules.yaml"))
        result = engine.evaluate("Ignore previous instructions")
        if result.hard_block:
            # return BLOCK immediately — do not call sidecar
    """

    def __init__(self, config_path: Path) -> None:
        """
        Load and pre-compile all rules at startup.

        Args:
            config_path: absolute or relative path to rules.yaml

        Raises:
            FileNotFoundError: if config_path does not exist
            yaml.YAMLError:    if the file is not valid YAML
        """
        if not config_path.exists():
            raise FileNotFoundError(
                f"RuleEngine: config file not found: {config_path}"
            )
        self._rules = self._load(config_path)

    def _load(self, path: Path) -> list[dict]:
        """
        Parse rules.yaml and pre-compile every regex pattern.

        Malformed patterns are skipped with a printed warning.
        A rule with zero compilable patterns is excluded entirely.
        A rule with at least one valid pattern is included.
        """
        with open(path) as f:
            config = yaml.safe_load(f)

        compiled_rules: list[dict] = []

        for rule in config.get("rules", []):
            rule_id   = rule.get("id", "unknown")
            compiled_patterns: list[re.Pattern] = []

            for pattern in rule.get("patterns", []):
                try:
                    compiled_patterns.append(
                        re.compile(pattern, re.IGNORECASE)
                    )
                except re.error as e:
                    # One bad pattern must never disable the whole rule
                    print(
                        f"[RuleEngine] WARNING: skipping malformed pattern "
                        f"in rule {rule_id!r}: {pattern!r} — {e}"
                    )

            if compiled_patterns:
                compiled_rules.append({
                    "id":       rule_id,
                    "signal":   rule.get("signal", "unknown"),
                    "severity": rule.get("severity", "low"),
                    "compiled": compiled_patterns,
                })

        return compiled_rules

    def evaluate(self, text: object) -> RuleResult:
        """
        Evaluate text against all loaded rules.

        Args:
            text: payload to evaluate — any type is accepted.
                  Non-strings are coerced via str() so that dicts
                  from on_tool_call and on_memory are handled safely.

        Returns:
            RuleResult with all matches, highest score, hard_block flag,
            and deduplicated signal list.
        """
        # Coerce non-string input — on_tool_call passes dicts
        if not isinstance(text, str):
            text = str(text)

        result = RuleResult()

        for rule in self._rules:
            for pattern in rule["compiled"]:
                match = pattern.search(text)
                if match:
                    # Record the match
                    result.matches.append(RuleMatch(
                        signal=rule["signal"],
                        severity=rule["severity"],
                        pattern_id=rule["id"],
                        matched_text=match.group(0),
                    ))

                    # Score is max weight seen — never a sum
                    weight = _SEVERITY_WEIGHTS.get(rule["severity"], 0.25)
                    result.score = max(result.score, weight)

                    # Critical severity → hard block
                    if rule["severity"] == "critical":
                        result.hard_block = True

                    # First match per rule is enough — move to next rule
                    break

        return result

    @property
    def rule_count(self) -> int:
        """Number of successfully loaded rules. Useful for health checks."""
        return len(self._rules)