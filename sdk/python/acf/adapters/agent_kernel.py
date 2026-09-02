"""
Agent Kernel guardrail adapter for ACF-SDK.

Integrates the ACF firewall as an InputGuardrail in Agent Kernel's guardrail
system. Sits alongside OpenAI and Bedrock as a guardrail option — but runs
locally, deterministically, with no API calls.

Usage in Agent Kernel config:

    guardrails:
      input:
        provider: acf

Or programmatically:

    from acf.adapters.agent_kernel import ACFInputGuardrail

    input_guard = ACFInputGuardrail(firewall=fw)

Output guardrails are deliberately not provided yet. Checking agent replies
needs the on_outbound hook, which is v2. Routing replies through on_prompt
looks like it works but stamps them provenance="user", so agent output is
scored at full user trust against prompt.rego's inbound rules — which blocks
the agent's own refusal messages ("I can't help with that. Asking me to
ignore previous instructions..."). ACFOutputGuardrail will return here once
on_outbound exists.
"""
from __future__ import annotations

import logging
from typing import List, Optional

from ..firewall import Firewall
from ..models import Decision, SanitiseResult, FirewallError

logger = logging.getLogger(__name__)

try:
    from agentkernel.guardrail.guardrail import (
        GuardrailAction,
        GuardrailResult,
        InputGuardrail,
        InputGuardrailFactory,
    )
    from agentkernel.core.model import AgentRequestText
    from agentkernel.core.base import Agent, Session

    _AK_AVAILABLE = True
except ImportError:
    _AK_AVAILABLE = False


def _check_ak():
    if not _AK_AVAILABLE:
        raise ImportError(
            "Agent Kernel is not installed. Install with: pip install acf-sdk[agentkernel]"
        )


class ACFInputGuardrail(InputGuardrail if _AK_AVAILABLE else object):
    """ACF firewall as an Agent Kernel input guardrail.

    Runs fw.on_prompt() on every incoming request. Maps ACF decisions to
    Agent Kernel's GuardrailAction:
        Decision.ALLOW    -> GuardrailAction.ALLOW
        Decision.BLOCK    -> GuardrailAction.BLOCK
        SanitiseResult    -> GuardrailAction.OVERRIDE (cleaned text)

    Every request in the batch is screened. A BLOCK anywhere in the batch
    rejects the whole batch; otherwise any sanitised requests have their
    prompt rewritten in place before ALLOW/OVERRIDE is returned.
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
        """Check every request through the ACF firewall."""
        sanitised: List[str] = []

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

            # A block rejects the whole batch, so there is nothing left to
            # screen — the remaining requests never reach the agent.
            if result == Decision.BLOCK:
                return GuardrailResult(
                    action=GuardrailAction.BLOCK,
                    message="ACF: input blocked by firewall policy",
                )

            if isinstance(result, SanitiseResult):
                request.prompt = result.sanitised_text
                sanitised.append(result.sanitised_text)
                # Keep screening. Returning here would let every later
                # request through unchecked.

        if not sanitised:
            return GuardrailResult(action=GuardrailAction.ALLOW)

        # override_text is a single string and cannot express a batch, so the
        # rewritten request.prompt values above are the reliable channel. Fill
        # it in for the single-request case, which is the common one.
        return GuardrailResult(
            action=GuardrailAction.OVERRIDE,
            override_text=sanitised[0] if len(sanitised) == 1 else None,
            message=f"ACF: {len(sanitised)} input(s) sanitised",
        )


# Register with Agent Kernel's factory so users can just set
# provider: acf in their config.
if _AK_AVAILABLE:
    try:
        InputGuardrailFactory.register("acf", ACFInputGuardrail)
    except Exception as e:
        # Some versions may not support registration at import time. Users can
        # still instantiate ACFInputGuardrail directly — but say so, rather
        # than leaving `provider: acf` silently unresolvable.
        logger.warning(
            "acf-sdk: could not register 'acf' input guardrail with Agent Kernel "
            "(%s). Instantiate ACFInputGuardrail directly instead.", e
        )
