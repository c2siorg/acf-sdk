import logging
from typing import Any, Dict, Optional


logger = logging.getLogger(__name__)


class RiskAggregator:
    """Fast-path risk scorer for the ACF evaluation phase.

    This implementation is intentionally stateless so it can run within the
    synchronous, low-latency evaluation path. It only inspects the current
    payload and avoids database access, cache lookups, or any external calls.

    The public API includes placeholder hooks for future hybrid scoring via
    ``stateful_context`` and ``external_risk_signal``. Those values are
    currently ignored for scoring so the fast-path behavior remains fully
    deterministic and self-contained.
    """

    def __init__(
        self,
        obfuscation_weight: float = 0.4,
        lexical_weight: float = 0.3,
        provenance_weight: float = 0.3,
        lexical_saturation_threshold: float = 5.0,
    ) -> None:
        self.obfuscation_weight = self._clamp(obfuscation_weight)
        self.lexical_weight = self._clamp(lexical_weight)
        self.provenance_weight = self._clamp(provenance_weight)
        self.lexical_saturation_threshold = max(
            float(lexical_saturation_threshold), 1.0
        )

    def compute_risk(
        self,
        payload: Dict[str, Any],
        stateful_context: Optional[Dict[str, Any]] = None,
        external_risk_signal: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Compute a normalized risk score and enforcement decision.

        Args:
            payload: Current telemetry payload under evaluation.
            stateful_context: Reserved for a future async/stateful scorer.
            external_risk_signal: Reserved for future external enrichment.

        Returns:
            A dictionary with ``risk_score`` and the final enforcement
            ``decision``.
        """
        telemetry_data = payload.get("telemetry_data") or {}
        delta = telemetry_data.get("delta") or {}
        provenance_metadata = payload.get("provenance_metadata") or {}

        obfuscation_severity = self._clamp(
            self._to_float(delta.get("obfuscation_severity", 0.0), default=0.0)
        )
        lexical_score = self._normalize_lexical_score(
            delta.get("lexical_hits", 0)
        )
        trust_weight = self._clamp(
            self._to_float(
                provenance_metadata.get("trust_weight", 1.0), default=1.0
            )
        )

        logger.debug(
            "RiskAggregator input signals: "
            "obfuscation_severity=%s lexical_score=%s trust_weight=%s "
            "stateful_context_present=%s external_risk_signal_present=%s",
            obfuscation_severity,
            lexical_score,
            trust_weight,
            stateful_context is not None,
            external_risk_signal is not None,
        )

        risk_score = (
            self.obfuscation_weight * obfuscation_severity
            + self.lexical_weight * lexical_score
            + self.provenance_weight * (1.0 - trust_weight)
        )

        total_weight = (
            self.obfuscation_weight
            + self.lexical_weight
            + self.provenance_weight
        )
        if total_weight > 0:
            risk_score = risk_score / total_weight

        if external_risk_signal is not None:
            external_signal = self._clamp(external_risk_signal)
            risk_score = (risk_score + external_signal) / 2.0

        risk_score = round(self._clamp(risk_score), 4)
        decision = self._decision(risk_score)

        logger.info(
            "RiskAggregator output: risk_score=%s decision=%s",
            risk_score,
            decision,
        )

        return {
            "risk_score": risk_score,
            "decision": decision,
        }

    def _normalize_lexical_score(self, lexical_hits: Any) -> float:
        """Normalize lexical scanner output to a 0-1 risk contribution.

        The scanner may emit a pre-normalized score, a raw integer hit count,
        or a collection of matches. Raw counts saturate at
        ``self.lexical_saturation_threshold`` to keep scoring stable and
        predictable.
        """
        if isinstance(lexical_hits, (list, tuple, set, dict)):
            lexical_hits = len(lexical_hits)

        lexical_value = self._to_float(lexical_hits, default=0.0)

        if lexical_value <= 0:
            return 0.0
        if lexical_value <= 1.0:
            return round(self._clamp(lexical_value), 4)

        return round(
            min(lexical_value / self.lexical_saturation_threshold, 1.0),
            4,
        )

    def _decision(self, risk_score: float) -> str:
        """Map normalized risk score to the enforcement decision."""
        if risk_score >= 0.7:
            return "BLOCK"
        if risk_score >= 0.4:
            return "SANITIZE"
        return "ALLOW"

    @staticmethod
    def _to_float(value: Any, default: float) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _clamp(value: float) -> float:
        return max(0.0, min(float(value), 1.0))
