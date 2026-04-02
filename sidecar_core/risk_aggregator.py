import logging
from typing import Any, Dict


logger = logging.getLogger(__name__)


class RiskAggregator:
    """Risk Aggregator (PDP - Aggregate Stage).

    Combines normalized signals into a single risk score.

    - Operates in O(1) time (fixed signal schema, no loops).
    - Stateless in v1 (state field remains null/untouched).
    - Does NOT perform policy decisions (handled by Policy Engine).
    - Designed to integrate with async stateful signals in future
      (external_risk via risk_context enrichment).
    - Strictly read-only on signals; only writes score back to context.
    """

    WEIGHTS = {
        "obfuscation": 0.4,
        "lexical": 0.3,
        "provenance": 0.2,
        "external": 0.1,
    }

    def __init__(self, weights: Dict[str, float] = None) -> None:
        """Initialize with optional custom weights.

        Args:
            weights: Override default WEIGHTS dict. Keys: obfuscation,
                lexical, provenance, external.
        """
        if weights is None:
            self.weights = self.WEIGHTS.copy()
        else:
            self.weights = weights

    def aggregate_risk(self, risk_context: Dict[str, Any]) -> Dict[str, Any]:
        """Aggregate normalized signals into a single risk score.

        Updates risk_context in-place with computed score.

        Args:
            risk_context: Dict with structure:
                {
                    "signals": {
                        "obfuscation_severity": float [0-1],
                        "lexical_score": float [0-1],
                        "provenance_trust": float [0-1],
                        "external_risk": float [0-1] (optional, default 0),
                    },
                    "session_id": str,
                    "state": None or dict,
                    ...
                }

        Returns:
            Updated risk_context with "score" field added.
        """
        signals = risk_context.get("signals", {})

        obfuscation_severity = self._to_float(
            signals.get("obfuscation_severity", 0.0), default=0.0
        )
        lexical_score = self._to_float(
            signals.get("lexical_score", 0.0), default=0.0
        )
        provenance_trust = self._to_float(
            signals.get("provenance_trust", 1.0), default=1.0
        )
        external_risk = self._to_float(
            signals.get("external_risk", 0.0), default=0.0
        )

        logger.debug(
            "Aggregating signals: obfuscation=%s lexical=%s "
            "provenance_trust=%s external=%s",
            obfuscation_severity,
            lexical_score,
            provenance_trust,
            external_risk,
        )

        score = (
            self.weights["obfuscation"] * obfuscation_severity
            + self.weights["lexical"] * lexical_score
            + self.weights["provenance"] * (1.0 - provenance_trust)
            + self.weights["external"] * external_risk
        )

        score = round(self._clamp(score), 4)

        risk_context["score"] = score

        logger.debug(
            "Risk aggregation complete: score=%s session_id=%s",
            score,
            risk_context.get("session_id"),
        )

        return risk_context

    @staticmethod
    def _to_float(value: Any, default: float) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _clamp(value: float) -> float:
        return max(0.0, min(float(value), 1.0))
