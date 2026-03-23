"""Risk context contract between aggregate and policy stages.

This module defines a fixed-size, O(1) aggregation surface for policy input.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


_SIGNAL_OBFUSCATION = "obfuscation"
_SIGNAL_LEXICAL = "lexical"
_SIGNAL_SEMANTIC = "semantic"
_SIGNAL_PROVENANCE = "provenance"

ALLOWED_SIGNALS = {
    _SIGNAL_OBFUSCATION,
    _SIGNAL_LEXICAL,
    _SIGNAL_SEMANTIC,
    _SIGNAL_PROVENANCE,
}

WEIGHTS = {
    _SIGNAL_OBFUSCATION: 0.3,
    _SIGNAL_LEXICAL: 0.3,
    _SIGNAL_SEMANTIC: 0.2,
    _SIGNAL_PROVENANCE: 0.2,
}

# TODO(v2): evolve hook multipliers into policy-configured profiles.
HOOK_MULTIPLIERS = {
    "on_prompt": 1.0,
    "on_context": 1.0,
    "on_tool_call": 1.1,
    "on_memory": 1.0,
}


def _clamp01(value: float) -> float:
    if value < 0.0:
        return 0.0
    if value > 1.0:
        return 1.0
    return value


def _normalize_signals(signals: dict[str, float]) -> dict[str, float]:
    """Return a fixed-size signal map, ignoring non-allowed keys."""

    # Explicit fixed-key extraction keeps aggregation O(1), even if callers
    # pass additional keys.
    return {
        _SIGNAL_OBFUSCATION: _clamp01(
            float(signals.get(_SIGNAL_OBFUSCATION, 0.0))
        ),
        _SIGNAL_LEXICAL: _clamp01(float(signals.get(_SIGNAL_LEXICAL, 0.0))),
        _SIGNAL_SEMANTIC: _clamp01(float(signals.get(_SIGNAL_SEMANTIC, 0.0))),
        _SIGNAL_PROVENANCE: _clamp01(
            float(signals.get(_SIGNAL_PROVENANCE, 0.0))
        ),
    }


@dataclass(frozen=True)
class RiskContext:
    """Normalized policy input object produced by the aggregator."""

    score: float
    signals: dict[str, float]
    provenance: dict[str, Any]
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "signals": self.signals,
            "provenance": self.provenance,
            "metadata": self.metadata,
        }


def aggregate_risk(
    *,
    signals: dict[str, float],
    provenance: dict[str, Any],
    metadata: dict[str, Any],
) -> RiskContext:
    """Build a fixed-shape `RiskContext` with O(1) weighted scoring.

    Expected signals keys: obfuscation, lexical, semantic, provenance.
    Missing keys default to 0.0. All values are clamped to [0.0, 1.0].
    """

    normalized_signals = _normalize_signals(signals)

    normalized_provenance = {
        "execution_id": str(provenance.get("execution_id", "")),
        "trusted": bool(provenance.get("trusted", False)),
        "nonce_valid": bool(provenance.get("nonce_valid", False)),
    }

    normalized_metadata = {
        "hook": str(metadata.get("hook", "")),
        "timestamp": int(metadata.get("timestamp", 0)),
    }

    score = _clamp01(
        (
            WEIGHTS[_SIGNAL_OBFUSCATION]
            * normalized_signals[_SIGNAL_OBFUSCATION]
        )
        + (WEIGHTS[_SIGNAL_LEXICAL] * normalized_signals[_SIGNAL_LEXICAL])
        + (WEIGHTS[_SIGNAL_SEMANTIC] * normalized_signals[_SIGNAL_SEMANTIC])
        + (
            WEIGHTS[_SIGNAL_PROVENANCE]
            * normalized_signals[_SIGNAL_PROVENANCE]
        )
    )

    trust_penalty = 0.2 if not normalized_provenance["trusted"] else 0.0
    nonce_penalty = 0.1 if not normalized_provenance["nonce_valid"] else 0.0
    score = _clamp01(score + trust_penalty + nonce_penalty)

    hook = normalized_metadata["hook"]
    hook_multiplier = HOOK_MULTIPLIERS.get(hook, 1.0)
    score = _clamp01(score * hook_multiplier)

    return RiskContext(
        score=score,
        signals=normalized_signals,
        provenance=normalized_provenance,
        metadata=normalized_metadata,
    )
