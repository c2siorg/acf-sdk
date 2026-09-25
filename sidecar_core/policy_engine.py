import logging
from typing import Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, Field

from sidecar_core.risk_aggregator import RiskAggregator


logger = logging.getLogger(__name__)


class ProvenanceConfig(BaseModel):
    require_execution_id_binding: bool
    max_token_age_seconds: int


class NormalizationConfig(BaseModel):
    max_recursion_depth: int
    block_on_depth_exceeded: bool


class LexicalRule(BaseModel):
    id: str
    type: str
    pattern: str
    action: str


class RiskAggregatorWeights(BaseModel):
    obfuscation: float = 0.4
    lexical: float = 0.3
    provenance: float = 0.3


class RiskAggregatorConfig(BaseModel):
    weights: RiskAggregatorWeights = Field(
        default_factory=RiskAggregatorWeights
    )


class FirewallPolicy(BaseModel):
    version: str
    enforcement_mode: str = Field(pattern="^(blocking|monitoring)$")
    latency_budget_ms: int = 10
    provenance_layer: ProvenanceConfig
    normalization_layer: Optional[NormalizationConfig] = None
    lexical_layer: List[LexicalRule] = Field(default_factory=list)
    risk_aggregator: Optional[RiskAggregatorConfig] = None


def load_policy(filepath: str) -> FirewallPolicy:
    """Dynamically load and validate the YAML firewall policy."""
    with open(filepath, "r", encoding="utf-8") as file_handle:
        data = yaml.safe_load(file_handle) or {}

    policy = FirewallPolicy(**data)
    logger.info(
        "Loaded policy version=%s latency_budget_ms=%s",
        policy.version,
        policy.latency_budget_ms,
    )
    return policy


class PolicyEngine:
    """Policy Decision Point (PDP) - enforces policy decisions.

    Orchestrates the evaluation pipeline:
    1. Normalizes scanner outputs into fixed signal schema
    2. Calls RiskAggregator to compute risk score (O(1))
    3. Maps risk score to enforcement decision based on thresholds
    4. Applies enforcement_mode (blocking vs monitoring)
    5. Returns final decision + metadata for audit logging
    """

    DECISION_THRESHOLDS = {
        "allow": 0.4,
        "sanitize": 0.7,
        "block": 1.0,
    }

    def __init__(
        self,
        policy: FirewallPolicy,
        risk_aggregator: Optional[RiskAggregator] = None,
    ) -> None:
        self.policy = policy
        if risk_aggregator is not None:
            self.risk_aggregator = risk_aggregator
            return

        weights_dict = None
        if policy.risk_aggregator is not None:
            weights_dict = {
                "obfuscation": policy.risk_aggregator.weights.obfuscation,
                "lexical": policy.risk_aggregator.weights.lexical,
                "provenance": policy.risk_aggregator.weights.provenance,
                "external": 0.1,
            }
        self.risk_aggregator = RiskAggregator(weights=weights_dict)

    def evaluate_payload(
        self,
        payload: Dict[str, Any],
        scanner_outputs: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Evaluate payload and return enforcement decision.

        Pipeline:
        1. Normalize scanner outputs into risk_context.signals
        2. Aggregate signals into risk score
        3. Map score to decision
        4. Apply enforcement_mode

        Args:
            payload: Original request payload (contains telemetry, provenance).
            scanner_outputs: Normalized signal outputs from upstream scanners.

        Returns:
            Decision dict:
            {
                "decision": "ALLOW" | "SANITIZE" | "BLOCK",
                "score": float,
                "session_id": str,
                "monitored_decision": str (if enforcement_mode=monitoring),
            }
        """
        risk_context = self._build_risk_context(payload, scanner_outputs)

        result = self.risk_aggregator.aggregate_risk(risk_context)

        score = result.get("score", 0.0)
        computed_decision = self._score_to_decision(score)

        enforcement_mode = getattr(self.policy, "enforcement_mode", None)
        final_decision = computed_decision

        if enforcement_mode == "monitoring":
            result["monitored_decision"] = computed_decision
            final_decision = "ALLOW"

        result["decision"] = final_decision

        logger.debug(
            "PolicyEngine decision: version=%s decision=%s score=%s "
            "enforcement_mode=%s",
            self.policy.version,
            final_decision,
            score,
            enforcement_mode,
        )

        return result

    def _score_to_decision(self, score: float) -> str:
        """Map risk score to enforcement decision."""
        if score < self.DECISION_THRESHOLDS["allow"]:
            return "ALLOW"
        if score < self.DECISION_THRESHOLDS["sanitize"]:
            return "SANITIZE"
        return "BLOCK"

    def _build_risk_context(
        self,
        payload: Dict[str, Any],
        scanner_outputs: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Build normalized risk_context from payload and scanner outputs."""
        session_id = payload.get("session_id", "unknown")

        signals = self._normalize_signals(payload, scanner_outputs)

        risk_context: Dict[str, Any] = {
            "session_id": session_id,
            "signals": signals,
            "state": None,
        }

        return risk_context

    @staticmethod
    def _normalize_signals(
        payload: Dict[str, Any],
        scanner_outputs: Optional[Dict[str, Any]],
    ) -> Dict[str, float]:
        """Normalize scanner outputs to fixed signal schema."""
        signals: Dict[str, float] = {
            "obfuscation_severity": 0.0,
            "lexical_score": 0.0,
            "provenance_trust": 1.0,
            "external_risk": 0.0,
        }

        if scanner_outputs:
            signals["obfuscation_severity"] = float(
                scanner_outputs.get("obfuscation_severity", 0.0)
            )
            signals["lexical_score"] = float(
                scanner_outputs.get("lexical_score", 0.0)
            )
            signals["provenance_trust"] = float(
                scanner_outputs.get("provenance_trust", 1.0)
            )
            signals["external_risk"] = float(
                scanner_outputs.get("external_risk", 0.0)
            )

        return signals


def evaluate_policy(
    payload: Dict[str, Any],
    policy_path: str,
    scanner_outputs: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Convenience entrypoint for one-shot evaluation.

    Example integration after scanners run:

        scanner_outputs = {
            "obfuscation_severity": normalization_result.get(
                "obfuscation_severity", 0.0
            ),
            "lexical_score": lexical_scan_result.get("score", 0.0),
            "provenance_trust": provenance_result.get("trust_weight", 1.0),
        }
        decision = evaluate_policy(
            payload,
            "sidecar_core/firewall_policy.yaml",
            scanner_outputs,
        )
    """
    policy = load_policy(policy_path)
    engine = PolicyEngine(policy)
    return engine.evaluate_payload(
        payload,
        scanner_outputs=scanner_outputs,
    )
