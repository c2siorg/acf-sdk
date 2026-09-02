"""
Tests for the Agent Kernel guardrail adapter.

Agent Kernel is not a test dependency, so its modules are faked. The fakes are
installed by an autouse fixture and torn down afterwards — importing this file
must not leave mock entries in sys.modules for the rest of the session.

Only the input guardrail is covered: output guardrails need the on_outbound
hook (v2), so the adapter does not ship one.
"""
from __future__ import annotations

import importlib
import sys
from types import ModuleType
from unittest.mock import MagicMock

import pytest

from acf.models import Decision, SanitiseResult, FirewallError


# ── fake Agent Kernel surface ────────────────────────────────────────────────


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


class FakeInputGuardrailFactory:
    _registry = {}

    @classmethod
    def register(cls, name, klass):
        cls._registry[name] = klass


class FakeAgentRequestText:
    def __init__(self, prompt=""):
        self.prompt = prompt


class FakeAgent:
    name = "test-agent"


class FakeSession:
    def __init__(self, sid="test-session"):
        self.id = sid


def _module(name, **attrs):
    mod = ModuleType(name)
    for key, value in attrs.items():
        setattr(mod, key, value)
    return mod


@pytest.fixture(autouse=True)
def fake_agentkernel(monkeypatch):
    """Install fake agentkernel modules, then reload the adapter against them.

    monkeypatch.setitem on sys.modules restores the previous state at teardown,
    so no mock survives this module.
    """
    mods = {
        "agentkernel": _module("agentkernel"),
        "agentkernel.guardrail": _module("agentkernel.guardrail"),
        "agentkernel.guardrail.guardrail": _module(
            "agentkernel.guardrail.guardrail",
            GuardrailAction=FakeGuardrailAction,
            GuardrailResult=FakeGuardrailResult,
            InputGuardrail=FakeInputGuardrail,
            InputGuardrailFactory=FakeInputGuardrailFactory,
        ),
        "agentkernel.core": _module("agentkernel.core"),
        "agentkernel.core.model": _module(
            "agentkernel.core.model", AgentRequestText=FakeAgentRequestText
        ),
        "agentkernel.core.base": _module(
            "agentkernel.core.base", Agent=FakeAgent, Session=FakeSession
        ),
    }
    for name, mod in mods.items():
        monkeypatch.setitem(sys.modules, name, mod)

    import acf.adapters.agent_kernel as adapter

    monkeypatch.setitem(sys.modules, "acf.adapters.agent_kernel", adapter)
    yield importlib.reload(adapter)


@pytest.fixture
def guard_cls(fake_agentkernel):
    return fake_agentkernel.ACFInputGuardrail


# ── helpers ──────────────────────────────────────────────────────────────────


def make_firewall(return_value):
    """Build a mock Firewall where on_prompt returns the given value."""
    firewall = MagicMock()
    firewall.on_prompt.return_value = return_value
    return firewall


def make_request(text="hello"):
    return FakeAgentRequestText(prompt=text)


def sanitise(text):
    return SanitiseResult(
        decision=Decision.SANITISE,
        sanitised_payload=text.encode(),
        sanitised_text=text,
    )


# ── decision mapping ─────────────────────────────────────────────────────────


class TestACFInputGuardrail:

    def test_allow_passes_through(self, guard_cls):
        firewall = make_firewall(Decision.ALLOW)
        guard = guard_cls(firewall=firewall)
        result = guard.validate(FakeAgent(), FakeSession(), [make_request("hi")])
        assert result.action == FakeGuardrailAction.ALLOW

    def test_block_returns_block(self, guard_cls):
        firewall = make_firewall(Decision.BLOCK)
        guard = guard_cls(firewall=firewall)
        result = guard.validate(FakeAgent(), FakeSession(), [make_request("attack")])
        assert result.action == FakeGuardrailAction.BLOCK
        assert "blocked" in result.message.lower()

    def test_sanitise_returns_override(self, guard_cls):
        firewall = make_firewall(sanitise("clean text"))
        guard = guard_cls(firewall=firewall)
        result = guard.validate(FakeAgent(), FakeSession(), [make_request("dirty text")])
        assert result.action == FakeGuardrailAction.OVERRIDE
        assert result.override_text == "clean text"

    def test_sanitise_updates_request_prompt(self, guard_cls):
        firewall = make_firewall(sanitise("cleaned"))
        guard = guard_cls(firewall=firewall)
        request = make_request("original")
        guard.validate(FakeAgent(), FakeSession(), [request])
        assert request.prompt == "cleaned"

    def test_firewall_error_returns_block(self, guard_cls):
        firewall = MagicMock()
        firewall.on_prompt.side_effect = FirewallError("connection failed")
        guard = guard_cls(firewall=firewall)
        result = guard.validate(FakeAgent(), FakeSession(), [make_request("test")])
        assert result.action == FakeGuardrailAction.BLOCK
        assert "error" in result.message.lower()

    def test_empty_requests_allows(self, guard_cls):
        firewall = make_firewall(Decision.ALLOW)
        guard = guard_cls(firewall=firewall)
        result = guard.validate(FakeAgent(), FakeSession(), [])
        assert result.action == FakeGuardrailAction.ALLOW

    def test_non_string_prompt_skipped(self, guard_cls):
        firewall = make_firewall(Decision.ALLOW)
        guard = guard_cls(firewall=firewall)
        result = guard.validate(
            FakeAgent(), FakeSession(), [FakeAgentRequestText(prompt="")]
        )
        assert result.action == FakeGuardrailAction.ALLOW
        firewall.on_prompt.assert_not_called()


# ── batch screening (regression: every request must be checked) ───────────────


class TestBatchScreening:

    def test_screens_every_request_after_a_sanitise(self, guard_cls):
        """A sanitise on request[0] must not let request[1] through unchecked."""
        firewall = MagicMock()
        firewall.on_prompt.side_effect = [sanitise("cleaned"), Decision.BLOCK]
        guard = guard_cls(firewall=firewall)
        first, second = make_request("mildly bad"), make_request("outright attack")

        result = guard.validate(FakeAgent(), FakeSession(), [first, second])

        assert firewall.on_prompt.call_count == 2, "later requests were not screened"
        assert result.action == FakeGuardrailAction.BLOCK

    def test_all_clean_requests_are_screened(self, guard_cls):
        firewall = make_firewall(Decision.ALLOW)
        guard = guard_cls(firewall=firewall)
        requests = [make_request(f"q{i}") for i in range(3)]
        result = guard.validate(FakeAgent(), FakeSession(), requests)
        assert firewall.on_prompt.call_count == 3
        assert result.action == FakeGuardrailAction.ALLOW

    def test_multiple_sanitises_all_rewritten(self, guard_cls):
        firewall = MagicMock()
        firewall.on_prompt.side_effect = [sanitise("c0"), Decision.ALLOW, sanitise("c2")]
        guard = guard_cls(firewall=firewall)
        requests = [make_request("a"), make_request("b"), make_request("c")]

        result = guard.validate(FakeAgent(), FakeSession(), requests)

        assert [r.prompt for r in requests] == ["c0", "b", "c2"]
        assert result.action == FakeGuardrailAction.OVERRIDE
        # A single override_text cannot represent a batch; the rewritten
        # prompts above are the reliable channel.
        assert result.override_text is None
        assert "2 input(s) sanitised" in result.message

    def test_block_short_circuits_the_batch(self, guard_cls):
        firewall = MagicMock()
        firewall.on_prompt.side_effect = [Decision.BLOCK, Decision.ALLOW]
        guard = guard_cls(firewall=firewall)
        result = guard.validate(
            FakeAgent(), FakeSession(), [make_request("attack"), make_request("fine")]
        )
        assert firewall.on_prompt.call_count == 1
        assert result.action == FakeGuardrailAction.BLOCK


# ── packaging ────────────────────────────────────────────────────────────────


def test_no_output_guardrail_is_exported(fake_agentkernel):
    """Output checking needs on_outbound (v2); nothing should claim otherwise."""
    assert not hasattr(fake_agentkernel, "ACFOutputGuardrail")


def test_registers_input_provider(fake_agentkernel):
    registered = FakeInputGuardrailFactory._registry.get("acf")
    assert registered is fake_agentkernel.ACFInputGuardrail
