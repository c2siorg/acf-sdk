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
    """Thin orchestration layer for the sidecar evaluation phase.

    The engine stays synchronous and lightweight: scanner outputs are merged
    into the current payload and forwarded directly to ``RiskAggregator``.
    Future async/stateful enrichments can plug into the aggregator hooks
    without changing this call shape.
    """

    def __init__(
        self,
        policy: FirewallPolicy,
        risk_aggregator: Optional[RiskAggregator] = None,
    ) -> None:
        self.policy = policy
        if risk_aggregator is not None:
            self.risk_aggregator = risk_aggregator
            return

        weights = (
            policy.risk_aggregator.weights
            if policy.risk_aggregator is not None
            else RiskAggregatorWeights()
        )
        self.risk_aggregator = RiskAggregator(
            obfuscation_weight=weights.obfuscation,
            lexical_weight=weights.lexical,
            provenance_weight=weights.provenance,
        )

    def evaluate_payload(
        self,
        payload: Dict[str, Any],
        scanner_outputs: Optional[Dict[str, Any]] = None,
        stateful_context: Optional[Dict[str, Any]] = None,
        external_risk_signal: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Evaluate the current payload and return the final decision.

        ``scanner_outputs`` is expected to contain normalized or raw outputs
        from upstream scanners, such as ``lexical_hits`` or an updated
        ``obfuscation_severity``. These are merged into the payload before
        risk aggregation so the policy engine returns the final enforcement
        decision for the current request.
        """
        enriched_payload = self._merge_scanner_outputs(
            payload, scanner_outputs
        )
        result = self.risk_aggregator.compute_risk(
            enriched_payload,
            stateful_context=stateful_context,
            external_risk_signal=external_risk_signal,
        )

        enforcement_mode = getattr(self.policy, "enforcement_mode", None)
        computed_decision = result.get("decision")
        final_result = result

        if enforcement_mode == "monitoring":
            final_result = dict(result)
            if "decision" in final_result:
                final_result["monitored_decision"] = final_result["decision"]
                final_result["decision"] = "ALLOW"
            logged_decision = (
                f"{computed_decision} (monitoring - returning ALLOW)"
            )
        else:
            logged_decision = computed_decision

        logger.debug(
            "PolicyEngine decision: version=%s decision=%s risk_score=%s",
            self.policy.version,
            logged_decision,
            final_result.get("risk_score"),
        )

        return final_result

    @staticmethod
    def _merge_scanner_outputs(
        payload: Dict[str, Any], scanner_outputs: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        payload_copy: Dict[str, Any] = dict(payload)

        if not scanner_outputs:
            return payload_copy

        existing_telemetry = payload_copy.get("telemetry_data")
        if isinstance(existing_telemetry, dict):
            telemetry_data: Dict[str, Any] = dict(existing_telemetry)
        else:
            telemetry_data = {}
        payload_copy["telemetry_data"] = telemetry_data

        existing_delta = telemetry_data.get("delta")
        if isinstance(existing_delta, dict):
            delta: Dict[str, Any] = dict(existing_delta)
        else:
            delta = {}
        telemetry_data["delta"] = delta

        existing_provenance = payload_copy.get("provenance_metadata")
        if isinstance(existing_provenance, dict):
            provenance_metadata: Dict[str, Any] = dict(existing_provenance)
        else:
            provenance_metadata = {}
        payload_copy["provenance_metadata"] = provenance_metadata

        for key in ("obfuscation_severity", "lexical_hits"):
            if key in scanner_outputs:
                delta[key] = scanner_outputs[key]

        if "trust_weight" in scanner_outputs:
            provenance_metadata["trust_weight"] = scanner_outputs[
                "trust_weight"
            ]

        return payload_copy


def evaluate_policy(
    payload: Dict[str, Any],
    policy_path: str,
    scanner_outputs: Optional[Dict[str, Any]] = None,
    stateful_context: Optional[Dict[str, Any]] = None,
    external_risk_signal: Optional[float] = None,
) -> Dict[str, Any]:
    """Convenience entrypoint for one-shot evaluation.

    Example integration after scanners run:

        scanner_outputs = {
            "obfuscation_severity": normalization_result.get(
                "obfuscation_severity", 0.0
            ),
            "lexical_hits": lexical_scan_result.get("hits", 0),
            "trust_weight": provenance_result.get("trust_weight", 1.0),
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
        stateful_context=stateful_context,
        external_risk_signal=external_risk_signal,
    )
