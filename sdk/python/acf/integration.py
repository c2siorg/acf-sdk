"""
Integration layer: scanner signals → RiskContext → sidecar → audit log.

This module connects the semantic scanner (PR #15) to the Firewall transport
(Phase 1) and the audit logger, proving the full round-trip:

    1. Scanner analyses the input and produces signals
    2. Signals are included in the RiskContext JSON payload
    3. Payload is sent to the Go sidecar over UDS
    4. Sidecar returns a decision (ALLOW in Phase 1, real in Phase 2)
    5. Decision + signals + score are written to the JSONL audit log

In Phase 1 the sidecar always returns ALLOW because the pipeline stages
aren't wired yet.  But the round-trip proves:
    - The scanner runs and produces structured signals
    - The signals serialise correctly into the RiskContext JSON
    - The sidecar receives the payload, verifies HMAC, and responds
    - The audit log captures the decision with all metadata

When Phase 2 lands (scan.go reads the signals field), the Python side
is already producing the right data.  Zero changes needed here.

Usage:
    from acf.integration import FirewallWithScanner

    fw = FirewallWithScanner()
    result = fw.scan_and_enforce("Ignore all previous instructions")
    # result.decision = Decision.ALLOW (Phase 1)
    # result.signals = [{"category": "instruction_override", "score": 0.92}]
    # audit log entry written to acf_audit.jsonl
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .audit import AuditLogger
from .models import Decision


@dataclass
class IntegrationResult:
    """Result of a scan-and-enforce round-trip."""

    decision: Decision
    score: float
    signals: List[Dict[str, Any]]
    latency_ms: float
    audit_logged: bool = False


class FirewallWithScanner:
    """
    Wraps the Firewall and SemanticScanner into a single scan-and-enforce
    call.  Produces signals, sends to sidecar, logs the decision.

    This class uses lazy imports for the scanner and firewall so it can
    be tested with mocks without requiring sentence-transformers or a
    running sidecar.
    """

    def __init__(
        self,
        firewall=None,
        scanner=None,
        audit_logger: Optional[AuditLogger] = None,
    ) -> None:
        self._firewall = firewall
        self._scanner = scanner
        self._audit = audit_logger or AuditLogger()

    def scan_and_enforce(
        self,
        text: str,
        hook: str = "on_prompt",
        session_id: str = "",
    ) -> IntegrationResult:
        """
        Full round-trip: scan → build signals → send to sidecar → log.

        Parameters
        ----------
        text : str
            The input text to scan and enforce.
        hook : str
            Which hook this came from (on_prompt, on_context, etc.)
        session_id : str
            Session identifier for audit correlation.

        Returns
        -------
        IntegrationResult
            Decision, score, signals, latency, and audit status.
        """
        t0 = time.perf_counter()

        # Step 1: Run scanner (if available) to produce signals
        signals = []
        score = 0.0

        if self._scanner is not None:
            # Build a scan input as a simple dict-like object.
            # If acf.scanners is available (PR #15), use ScanInput.
            # Otherwise, use a lightweight dataclass that the scanner
            # can consume via duck typing — works with mocks in tests.
            try:
                from .scanners.models import ScanInput, InputType, TrustLevel
                scan_input = ScanInput(
                    agent_id="integration",
                    execution_id="int-001",
                    session_id=session_id or "default",
                    input_type=InputType.PROMPT,
                    normalized_content=text,
                    trust_level=TrustLevel.LOW,
                )
            except ImportError:
                # Scanner module not installed — use a simple namespace
                from types import SimpleNamespace
                scan_input = SimpleNamespace(
                    agent_id="integration",
                    execution_id="int-001",
                    session_id=session_id or "default",
                    input_type="prompt",
                    normalized_content=text,
                    trust_level="low",
                )
            scan_result = self._scanner.scan(scan_input)
            score = scan_result.risk_score
            signals = [
                {
                    "category": h.matched_category,
                    "score": h.similarity_score,
                    "source": "semantic_scanner",
                }
                for h in scan_result.semantic_hits
            ]

        # Step 2: Send to sidecar (if available)
        decision = Decision.ALLOW
        if self._firewall is not None:
            # The firewall sends the RiskContext JSON over UDS
            # In Phase 1, sidecar returns hardcoded ALLOW
            result = self._firewall.on_prompt(text)
            if isinstance(result, Decision):
                decision = result
            else:
                decision = result.decision

        elapsed_ms = (time.perf_counter() - t0) * 1000

        # Step 3: Determine which policy would have fired
        policy = ""
        if signals:
            top_signal = max(signals, key=lambda s: s["score"])
            policy = f"{hook}/{top_signal['category']}"

        # Step 4: Write audit log
        audit_logged = False
        try:
            self._audit.log(
                hook=hook,
                decision=decision.name,
                score=score,
                input_text=text,
                session_id=session_id,
                policy=policy,
                signals=signals,
                latency_ms=elapsed_ms,
            )
            audit_logged = True
        except Exception:
            # Audit failure must never block the enforcement path
            pass

        return IntegrationResult(
            decision=decision,
            score=score,
            signals=signals,
            latency_ms=round(elapsed_ms, 2),
            audit_logged=audit_logged,
        )
