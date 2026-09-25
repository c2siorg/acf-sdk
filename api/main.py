from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI, HTTPException

from acf import (
    Decision,
    Firewall,
    FirewallConnectionError,
    FirewallError,
    SanitiseResult,
)

from .models import HealthResponse, ValidateRequest, ValidateResponse
from .rules.engine import RuleEngine

logger = logging.getLogger(__name__)


_RULES_PATH = Path(__file__).parent / "config" / "rules.yaml"
_rule_engine = RuleEngine(_RULES_PATH)

logger.info(
    "RuleEngine initialised — %d rules loaded from %s",
    _rule_engine.rule_count,
    _RULES_PATH,
)

app = FastAPI(
    title="ACF Cognitive Firewall API",
    description=(
        "HTTP wrapper around the ACF Python SDK and UDS sidecar.\n\n"
        "Provides a /validate endpoint for easy demo and integration "
        "testing. The hot path remains SDK → UDS → sidecar — this "
        "API is for tooling and exploration only.\n\n"
        "**Layer 1:** In-process regex rule engine (fast rejection)\n\n"
        "**Layer 2:** Go sidecar via UDS (authoritative enforcement)"
    ),
    version="0.1.0",
)


def _get_firewall() -> Firewall:
    """
    Instantiate and return a Firewall instance.

    Defined as a plain function rather than a FastAPI Depends so
    that tests can patch it with unittest.mock.patch without
    async complexity.

    A new instance is created per request — Firewall opens a
    fresh UDS connection each time by design (see transport.py).
    """
    return Firewall()
def _call_hook(
    fw: Firewall,
    hook: str,
    payload: str | dict,
) -> Decision | SanitiseResult:
    """
    Dispatch to the correct Firewall method with the correct signature.

    Each hook has a different method signature in the SDK:
        on_prompt(text)            — single string arg
        on_context(chunks)         — list of strings
        on_tool_call(name, params) — two separate args
        on_memory(key, value, op)  — two separate args

    Cannot use getattr + single payload arg for all hooks because
    on_tool_call and on_memory expect unpacked arguments, not a dict.
    """
    if hook == "on_prompt":
        return fw.on_prompt(payload)

    elif hook == "on_context":
        chunks  = payload if isinstance(payload, list) else [payload]
        results = fw.on_context(chunks)
        # Return the worst decision across all chunks
        for chunk_result in results:
            if chunk_result.decision.value == 0x02:   # BLOCK
                return Decision.BLOCK
            if chunk_result.decision.value == 0x01:   # SANITISE
                return SanitiseResult(
                    decision=chunk_result.decision,
                    sanitised_payload=(
                        chunk_result.sanitised_text.encode()
                        if chunk_result.sanitised_text else b""
                    ),
                    sanitised_text=chunk_result.sanitised_text,
                )
        return Decision.ALLOW

    elif hook == "on_tool_call":
        if not isinstance(payload, dict):
            raise FirewallError(
                "on_tool_call requires a dict payload with "
                "'name' (str) and 'params' (dict) keys."
            )
        name   = payload.get("name", "")
        params = payload.get("params", {})
        return fw.on_tool_call(name, params)

    elif hook == "on_memory":
        if not isinstance(payload, dict):
            raise FirewallError(
                "on_memory requires a dict payload with "
                "'key' (str) and 'value' (str) keys."
            )
        key   = payload.get("key", "")
        value = payload.get("value", "")
        op    = payload.get("op", "write")
        return fw.on_memory(key, value, op)

    else:
        raise FirewallError(f"Unknown hook: {hook}")    


@app.get(
    "/health",
    response_model=HealthResponse,
    summary="Liveness check",
    description=(
        "Always returns HTTP 200. "
        "Sidecar reachability is reported in the response body "
        "but never causes a non-200 status — the API itself may "
        "still serve rule-based decisions even when the sidecar "
        "is temporarily unavailable."
    ),
)
def health() -> HealthResponse:
    """
    Check API liveness and sidecar reachability.

    Sidecar states:
        reachable     — Firewall() instantiated successfully
        unreachable   — FirewallConnectionError (socket not found)
        misconfigured — FirewallError (missing key, invalid hex)
    """
    try:
        _get_firewall()
        sidecar_status = "reachable"
    except FirewallConnectionError:
        sidecar_status = "unreachable"
    except FirewallError:
        sidecar_status = "misconfigured"

    return HealthResponse(status="ok", sidecar=sidecar_status)


@app.post(
    "/validate",
    response_model=ValidateResponse,
    summary="Evaluate a payload through the cognitive firewall",
    description=(
        "Runs the payload through two enforcement layers:\n\n"
        "1. **Rule engine** — in-process regex pre-filter. "
        "Critical matches return BLOCK immediately.\n\n"
        "2. **Sidecar** — Go enforcement kernel via UDS. "
        "Returns ALLOW, SANITISE, or BLOCK.\n\n"
        "The `rule_based` field in the response indicates which "
        "layer made the final decision."
    ),
)
def validate(request: ValidateRequest) -> ValidateResponse:
    """
    Evaluate a payload through the cognitive firewall.

    Flow:
        Stage 1 — rule engine pre-filter
            hard_block=True  → return BLOCK immediately
            hard_block=False → continue to sidecar

        Stage 2 — sidecar round-trip
            FirewallConnectionError → 503 (sidecar down)
            FirewallError           → 400 (misconfiguration)
            SanitiseResult          → SANITISE + scrubbed payload
            Decision.ALLOW          → ALLOW
            Decision.BLOCK          → BLOCK

        Stage 3 — merge and return
            Signals from rule engine included in every response.
    """
    # Normalise payload to string for rule engine.
    # on_tool_call and on_memory pass dicts — str() handles both.
    payload_text = (
        request.payload
        if isinstance(request.payload, str)
        else str(request.payload)
    )

    # ── Stage 1: rule-based pre-filter ───────────────────────────────────────
    rule_result = _rule_engine.evaluate(payload_text)

    if rule_result.hard_block:
        logger.info(
            "Rule-based BLOCK | hook=%s signals=%s score=%.2f payload=%r",
            request.hook.value,
            rule_result.signals,
            rule_result.score,
            payload_text[:80],
        )
        return ValidateResponse(
            decision="BLOCK",
            signals=rule_result.signals,
            score=rule_result.score,
            rule_based=True,
        )

    # ── Stage 2: sidecar round-trip ──────────────────────────────────────────
    try:
        fw      = _get_firewall()
        result = _call_hook(fw, request.hook.value, request.payload)

    except FirewallConnectionError as exc:
        # Sidecar not running.
        # Fail closed — never silently ALLOW when enforcement
        # is unavailable. Return 503 with clear recovery instructions.
        logger.error(
            "Sidecar unreachable | hook=%s error=%s",
            request.hook.value, exc,
        )
        raise HTTPException(
            status_code=503,
            detail=(
                "Sidecar is not reachable. "
                "Start it with: source .env.local && ./bin/acf-sidecar"
            ),
        ) from exc

    except FirewallError as exc:
        # Misconfiguration — missing HMAC key, invalid hex, etc.
        logger.error(
            "Firewall config error | hook=%s error=%s",
            request.hook.value, exc,
        )
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    if isinstance(result, SanitiseResult):
        decision_str      = "SANITISE"
        sanitised_payload = result.sanitised_text
    else:
        decision_str      = result.name
        sanitised_payload = None

    logger.info(
        "Sidecar decision | hook=%s decision=%s signals=%s score=%.2f",
        request.hook.value,
        decision_str,
        rule_result.signals,
        rule_result.score,
    )

    return ValidateResponse(
        decision=decision_str,
        sanitised_payload=sanitised_payload,
        signals=rule_result.signals,
        score=rule_result.score,
        rule_based=False,
    )