"""
Agent Kernel guardrail adapter for ACF-SDK.

Integrates the ACF firewall as an InputGuardrail and OutputGuardrail in
Agent Kernel's guardrail system. Sits alongside OpenAI and Bedrock as a
guardrail option — but runs locally, deterministically, with no API calls.

Usage in Agent Kernel config:

    guardrails:
      input:
        provider: acf
      output:
        provider: acf

Or programmatically:

    from acf.adapters.agent_kernel import ACFInputGuardrail, ACFOutputGuardrail

    input_guard = ACFInputGuardrail(firewall=fw)
    output_guard = ACFOutputGuardrail(firewall=fw)
"""
from __future__ import annotations

import logging
from typing import List, Optional

from ..firewall import Firewall
from ..models import Decision, SanitiseResult, FirewallError

logger = logging.getLogger(__name__)

try:
    from agentkernel.guardrail.guardrail import (
        BaseGuardrailUtil,
        GuardrailAction,
        GuardrailResult,
        InputGuardrail,
        InputGuardrailFactory,
        OutputGuardrail,
        OutputGuardrailFactory,
    )
    from agentkernel.core.model import (
        AgentReplyAny,
        AgentReplyText,
        AgentRequestText,
    )
    from agentkernel.core.base import Agent, Session

    _AK_AVAILABLE = True
except ImportError:
    _AK_AVAILABLE = False


def _check_ak():
    if not _AK_AVAILABLE:
        raise ImportError(
            "Agent Kernel is not installed. Install with: pip install agentkernel"
        )


class ACFInputGuardrail(InputGuardrail if _AK_AVAILABLE else object):
    """ACF firewall as an Agent Kernel input guardrail.

    Runs fw.on_prompt() on each incoming request. Maps ACF decisions to
    Agent Kernel's GuardrailAction:
        Decision.ALLOW    -> GuardrailAction.ALLOW
        Decision.BLOCK    -> GuardrailAction.BLOCK
        SanitiseResult    -> GuardrailAction.OVERRIDE (cleaned text)
    """

    def __init__(self, firewall: Optional[Firewall] = None, **kwargs):
        _check_ak()
        super().__init__(**kwargs)
        self._firewall = firewall or Firewall()

    def validate(
        self,
        agent: Agent,
        session: Session,
        requests: List[AgentRequestText],
    ) -> GuardrailResult:
        """Check each request through the ACF firewall."""
        for request in requests:
            text = getattr(request, "prompt", None)
            if not text or not isinstance(text, str):
                continue

            try:
                result = self._firewall.on_prompt(text)
            except FirewallError as e:
                logger.warning("acf-sdk: guardrail error on input: %s", e)
                # Fail-closed: block on firewall errors.
                return GuardrailResult(
                    action=GuardrailAction.BLOCK,
                    message=f"ACF firewall error: {e}",
                )

            if isinstance(result, SanitiseResult):
                request.prompt = result.sanitised_text
                return GuardrailResult(
                    action=GuardrailAction.OVERRIDE,
                    override_text=result.sanitised_text,
                    message="ACF: input sanitised",
                )

            if result == Decision.BLOCK:
                return GuardrailResult(
                    action=GuardrailAction.BLOCK,
                    message="ACF: input blocked by firewall policy",
                )

        return GuardrailResult(action=GuardrailAction.ALLOW)


class ACFOutputGuardrail(OutputGuardrail if _AK_AVAILABLE else object):
    """ACF firewall as an Agent Kernel output guardrail.

    Runs fw.on_prompt() on the agent's reply text as a basic output check.
    When on_outbound is added in ACF v2, this will switch to that hook.
    """

    def __init__(self, firewall: Optional[Firewall] = None, **kwargs):
        _check_ak()
        super().__init__(**kwargs)
        self._firewall = firewall or Firewall()

    def validate(
        self,
        agent: Agent,
        session: Session,
        request: AgentRequestText,
        reply: AgentReplyAny,
    ) -> GuardrailResult:
        """Check agent output through the ACF firewall."""
        text = None
        if isinstance(reply, AgentReplyText):
            text = reply.response
        elif hasattr(reply, "response"):
            text = str(reply.response)

        if not text:
            return GuardrailResult(action=GuardrailAction.ALLOW)

        try:
            result = self._firewall.on_prompt(text)
        except FirewallError as e:
            logger.warning("acf-sdk: guardrail error on output: %s", e)
            return GuardrailResult(
                action=GuardrailAction.BLOCK,
                message=f"ACF firewall error: {e}",
            )

        if isinstance(result, SanitiseResult):
            if isinstance(reply, AgentReplyText):
                reply.response = result.sanitised_text
            return GuardrailResult(
                action=GuardrailAction.OVERRIDE,
                override_text=result.sanitised_text,
                message="ACF: output sanitised",
            )

        if result == Decision.BLOCK:
            return GuardrailResult(
                action=GuardrailAction.BLOCK,
                message="ACF: output blocked by firewall policy",
            )

        return GuardrailResult(action=GuardrailAction.ALLOW)


# Register with Agent Kernel's factory so users can just set
# provider: acf in their config.
if _AK_AVAILABLE:
    try:
        InputGuardrailFactory.register("acf", ACFInputGuardrail)
        OutputGuardrailFactory.register("acf", ACFOutputGuardrail)
    except Exception:
        # Factory might not support registration at import time in all
        # versions. Users can still instantiate directly.
        pass