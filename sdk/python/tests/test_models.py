"""Tests for acf.models — Decision enum and result dataclasses."""
import pytest
from acf.models import Decision, SanitiseResult, ChunkResult, FirewallError, FirewallConnectionError


def test_decision_members():
    members = {m.name for m in Decision}
    assert members == {"ALLOW", "SANITISE", "BLOCK"}


def test_decision_values():
    assert Decision.ALLOW.value    == 0x00
    assert Decision.SANITISE.value == 0x01
    assert Decision.BLOCK.value    == 0x02


def test_decision_from_byte_allow():
    assert Decision.from_byte(0x00) == Decision.ALLOW


def test_decision_from_byte_sanitise():
    assert Decision.from_byte(0x01) == Decision.SANITISE


def test_decision_from_byte_block():
    assert Decision.from_byte(0x02) == Decision.BLOCK


def test_decision_from_byte_invalid():
    with pytest.raises(ValueError, match="Unknown decision byte"):
        Decision.from_byte(0xFF)


def test_sanitise_result_fields():
    r = SanitiseResult(
        decision=Decision.SANITISE,
        sanitised_payload=b"safe",
        sanitised_text="safe",
    )
    assert r.decision == Decision.SANITISE
    assert r.sanitised_payload == b"safe"
    assert r.sanitised_text == "safe"


def test_sanitise_result_default_text():
    r = SanitiseResult(decision=Decision.SANITISE, sanitised_payload=b"x")
    assert r.sanitised_text is None


def test_chunk_result_fields():
    r = ChunkResult(original="raw", decision=Decision.ALLOW)
    assert r.original == "raw"
    assert r.decision == Decision.ALLOW
    assert r.sanitised_text is None


def test_firewall_error_is_exception():
    assert issubclass(FirewallError, Exception)


def test_firewall_connection_error_inherits():
    assert issubclass(FirewallConnectionError, FirewallError)
