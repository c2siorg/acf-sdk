"""Tests for acf.sdk_integration.risk_context."""

from acf.sdk_integration.risk_context import (
    RiskContext,
    WEIGHTS,
    aggregate_risk,
)


def test_risk_context_structure():
    ctx = aggregate_risk(
        signals={
            "obfuscation": 0.8,
            "lexical": 0.7,
            "semantic": 0.5,
            "provenance": 1.0,
        },
        provenance={
            "execution_id": "exec-123",
            "trusted": True,
            "nonce_valid": True,
        },
        metadata={
            "hook": "on_prompt",
            "timestamp": 1710000000,
        },
    )

    assert isinstance(ctx, RiskContext)

    payload = ctx.to_dict()
    assert set(payload.keys()) == {
        "score",
        "signals",
        "provenance",
        "metadata",
    }
    assert set(payload["signals"].keys()) == {
        "obfuscation",
        "lexical",
        "semantic",
        "provenance",
    }
    assert set(payload["provenance"].keys()) == {
        "execution_id",
        "trusted",
        "nonce_valid",
    }
    assert set(payload["metadata"].keys()) == {"hook", "timestamp"}

    opa_input = {"input": payload}
    assert "input" in opa_input
    assert opa_input["input"]["metadata"]["hook"] == "on_prompt"


def test_score_bounds():
    ctx = aggregate_risk(
        signals={
            "obfuscation": 99.0,
            "lexical": 50.0,
            "semantic": 22.0,
            "provenance": 9.0,
        },
        provenance={
            "execution_id": "exec-bounds",
            "trusted": False,
            "nonce_valid": False,
        },
        metadata={
            "hook": "on_context",
            "timestamp": 1710000001,
        },
    )

    assert 0.0 <= ctx.score <= 1.0


def test_weighted_scoring():
    ctx = aggregate_risk(
        signals={
            "obfuscation": 0.5,
            "lexical": 0.5,
            "semantic": 0.5,
            "provenance": 0.5,
        },
        provenance={
            "execution_id": "exec-weighted",
            "trusted": True,
            "nonce_valid": True,
        },
        metadata={
            "hook": "on_prompt",
            "timestamp": 1710000100,
        },
    )

    expected = (
        (WEIGHTS["obfuscation"] * 0.5)
        + (WEIGHTS["lexical"] * 0.5)
        + (WEIGHTS["semantic"] * 0.5)
        + (WEIGHTS["provenance"] * 0.5)
    )
    assert round(ctx.score, 2) == round(expected, 2)


def test_deterministic_output():
    kwargs = {
        "signals": {
            "obfuscation": 0.21,
            "lexical": 0.49,
            "semantic": 0.13,
            "provenance": 0.77,
        },
        "provenance": {
            "execution_id": "exec-deterministic",
            "trusted": True,
            "nonce_valid": True,
        },
        "metadata": {
            "hook": "on_tool_call",
            "timestamp": 1710000002,
        },
    }

    a = aggregate_risk(**kwargs)
    b = aggregate_risk(**kwargs)

    assert a.to_dict() == b.to_dict()


def test_signal_normalization():
    ctx = aggregate_risk(
        signals={
            "obfuscation": -10.0,
            "lexical": 0.25,
            "semantic": 100.0,
            "provenance": -1.0,
        },
        provenance={
            "execution_id": "exec-normalize",
            "trusted": 1,
            "nonce_valid": 0,
        },
        metadata={
            "hook": "on_memory",
            "timestamp": "1710000003",
        },
    )

    assert ctx.signals["obfuscation"] == 0.0
    assert ctx.signals["lexical"] == 0.25
    assert ctx.signals["semantic"] == 1.0
    assert ctx.signals["provenance"] == 0.0

    assert ctx.provenance["trusted"] is True
    assert ctx.provenance["nonce_valid"] is False
    assert ctx.metadata["timestamp"] == 1710000003


def test_missing_signals_defaults():
    ctx = aggregate_risk(
        signals={},
        provenance={
            "execution_id": "exec-defaults",
            "trusted": True,
            "nonce_valid": True,
        },
        metadata={
            "hook": "on_prompt",
            "timestamp": 1710000200,
        },
    )

    assert ctx.signals["obfuscation"] == 0.0
    assert ctx.signals["lexical"] == 0.0
    assert ctx.signals["semantic"] == 0.0
    assert ctx.signals["provenance"] == 0.0
