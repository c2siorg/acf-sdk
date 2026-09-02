"""
Tests for the Agent Kernel guardrail adapter.

Mocks agentkernel dependencies so tests run without it installed.
Verifies decision mapping, error handling, and sanitise override logic.
"""
from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest

# Mock agentkernel before importing the adapter
mock_guardrail = MagicMock()
mock_core_model = MagicMock()
mock_core_base = MagicMock()

sys.modules["agentkernel"] = MagicMock()
sys.modules["agentkernel.guardrail"] = MagicMock()
sys.modules["agentkernel.guardrail.guardrail"] = mock_guardrail
sys.modules["agentkernel.core"] = MagicMock()
sys.modules["agentkernel.core.model"] = mock_core_model
sys.modules["agentkernel.core.base"] = mock_core_base


# Define fake classes that the adapter expects
class FakeGuardrailAction:
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    OVERRIDE = "OVERRIDE"


class FakeGuardrailResult:
    def __init__(self, action, message=None, override_text=None):
        self.action = action
        self.message = message
        self.override_text = override_text


class FakeInputGuardrail:
    def __init__(self, **kwargs):
        pass


class FakeOutputGuardrail:
    def __init__(self, **kwargs):
        pass


class FakeInputGuardrailFactory:
    _registry = {}

    @classmethod
    def register(cls, name, klass):
        cls._registry[name] = klass


class FakeOutputGuardrailFactory:
    _registry = {}

    @classmethod
    def register(cls, name, klass):
        cls._registry[name] = klass


class FakeAgentRequestText:
    def __init__(self, prompt=""):
        self.prompt = prompt


class FakeAgentReplyText:
    def __init__(self, response="", prompt=""):
        self.response = response
        self.prompt = prompt


class FakeAgent:
    name = "test-agent"


class FakeSession:
    def __init__(self, sid="test-session"):
        self.id = sid


# Wire up the mocks
mock_guardrail.GuardrailAction = FakeGuardrailAction
mock_guardrail.GuardrailResult = FakeGuardrailResult
mock_guardrail.InputGuardrail = FakeInputGuardrail
mock_guardrail.OutputGuardrail = FakeOutputGuardrail
mock_guardrail.InputGuardrailFactory = FakeInputGuardrailFactory
mock_guardrail.OutputGuardrailFactory = FakeOutputGuardrailFactory
mock_guardrail.BaseGuardrailUtil = MagicMock()
mock_core_model.AgentRequestText = FakeAgentRequestText
mock_core_model.AgentReplyText = FakeAgentReplyText
mock_core_model.AgentReplyAny = FakeAgentReplyText
mock_core_base.Agent = FakeAgent
mock_core_base.Session = FakeSession

# Now import the adapter
from acf.adapters.agent_kernel import ACFInputGuardrail, ACFOutputGuardrail
from acf.models import Decision, SanitiseResult, FirewallError


# ── helpers ──────────────────────────────────────────────────────────────────


def make_firewall(return_value):
    """Build a mock Firewall where on_prompt returns the given value."""
    fw = MagicMock()
    fw.on_prompt.return_value = return_value
    return fw


def make_request(text="hello"):
    return FakeAgentRequestText(prompt=text)


def make_reply(text="response"):
    return FakeAgentReplyText(response=text, prompt="query")


# ── InputGuardrail tests ─────────────────────────────────────────────────────


class TestACFInputGuardrail:

    def test_allow_passes_through(self):
        fw = make_firewall(Decision.ALLOW)
        guard = ACFInputGuardrail(firewall=fw)
        result = guard.validate(FakeAgent(), FakeSession(), [make_request("hi")])
        assert result.action == FakeGuardrailAction.ALLOW

    def test_block_returns_block(self):
        fw = make_firewall(Decision.BLOCK)
        guard = ACFInputGuardrail(firewall=fw)
        result = guard.validate(FakeAgent(), FakeSession(), [make_request("attack")])
        assert result.action == FakeGuardrailAction.BLOCK
        assert "blocked" in result.message.lower()

    def test_sanitise_returns_override(self):
        sanitised = SanitiseResult(
            decision=Decision.SANITISE,
            sanitised_payload=b"clean text",
            sanitised_text="clean text",
        )
        fw = make_firewall(sanitised)
        guard = ACFInputGuardrail(firewall=fw)
        req = make_request("dirty text")
        result = guard.validate(FakeAgent(), FakeSession(), [req])
        assert result.action == FakeGuardrailAction.OVERRIDE
        assert result.override_text == "clean text"

    def test_sanitise_updates_request_prompt(self):
        sanitised = SanitiseResult(
            decision=Decision.SANITISE,
            sanitised_payload=b"cleaned",
            sanitised_text="cleaned",
        )
        fw = make_firewall(sanitised)
        guard = ACFInputGuardrail(firewall=fw)
        req = make_request("original")
        guard.validate(FakeAgent(), FakeSession(), [req])
        assert req.prompt == "cleaned"

    def test_firewall_error_returns_block(self):
        fw = MagicMock()
        fw.on_prompt.side_effect = FirewallError("connection failed")
        guard = ACFInputGuardrail(firewall=fw)
        result = guard.validate(FakeAgent(), FakeSession(), [make_request("test")])
        assert result.action == FakeGuardrailAction.BLOCK
        assert "error" in result.message.lower()

    def test_empty_requests_allows(self):
        fw = make_firewall(Decision.ALLOW)
        guard = ACFInputGuardrail(firewall=fw)
        result = guard.validate(FakeAgent(), FakeSession(), [])
        assert result.action == FakeGuardrailAction.ALLOW

    def test_non_string_prompt_skipped(self):
        fw = make_firewall(Decision.ALLOW)
        guard = ACFInputGuardrail(firewall=fw)
        req = FakeAgentRequestText(prompt="")
        result = guard.validate(FakeAgent(), FakeSession(), [req])
        assert result.action == FakeGuardrailAction.ALLOW
        fw.on_prompt.assert_not_called()


# ── OutputGuardrail tests ────────────────────────────────────────────────────


class TestACFOutputGuardrail:

    def test_allow_passes_through(self):
        fw = make_firewall(Decision.ALLOW)
        guard = ACFOutputGuardrail(firewall=fw)
        result = guard.validate(
            FakeAgent(), FakeSession(), make_request(), make_reply("safe output")
        )
        assert result.action == FakeGuardrailAction.ALLOW

    def test_block_returns_block(self):
        fw = make_firewall(Decision.BLOCK)
        guard = ACFOutputGuardrail(firewall=fw)
        result = guard.validate(
            FakeAgent(), FakeSession(), make_request(), make_reply("dangerous output")
        )
        assert result.action == FakeGuardrailAction.BLOCK

    def test_sanitise_returns_override(self):
        sanitised = SanitiseResult(
            decision=Decision.SANITISE,
            sanitised_payload=b"clean output",
            sanitised_text="clean output",
        )
        fw = make_firewall(sanitised)
        guard = ACFOutputGuardrail(firewall=fw)
        reply = make_reply("dirty output")
        result = guard.validate(
            FakeAgent(), FakeSession(), make_request(), reply
        )
        assert result.action == FakeGuardrailAction.OVERRIDE
        assert reply.response == "clean output"

    def test_empty_reply_allows(self):
        fw = make_firewall(Decision.ALLOW)
        guard = ACFOutputGuardrail(firewall=fw)
        reply = make_reply("")
        result = guard.validate(
            FakeAgent(), FakeSession(), make_request(), reply
        )
        assert result.action == FakeGuardrailAction.ALLOW
        fw.on_prompt.assert_not_called()

    def test_firewall_error_returns_block(self):
        fw = MagicMock()
        fw.on_prompt.side_effect = FirewallError("sidecar down")
        guard = ACFOutputGuardrail(firewall=fw)
        result = guard.validate(
            FakeAgent(), FakeSession(), make_request(), make_reply("output")
        )
        assert result.action == FakeGuardrailAction.BLOCK
        assert "error" in result.message.lower()