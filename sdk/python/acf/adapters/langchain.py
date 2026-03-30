"""
FirewallCallbackHandler — optional LangChain callback wrapper.
Hooks into LangChain's callback system to intercept tool calls (on_tool_start)
and LLM inputs (on_llm_start). Raises ToolException on BLOCK decisions.

Import is guarded: importing this module without langchain installed raises
ImportError with a helpful message (langchain is not a required dependency).
"""
from __future__ import annotations

from typing import Any
from uuid import UUID

try:
    from langchain_core.callbacks.base import BaseCallbackHandler
    from langchain_core.tools import ToolException
except ImportError as exc:
    raise ImportError(
        "langchain-core is required to use FirewallCallbackHandler. "
        "Install it with: pip install langchain-core"
    ) from exc

from ..firewall import Firewall
from ..models import Decision


class FirewallCallbackHandler(BaseCallbackHandler):
    """LangChain callback handler that enforces ACF policy on tool calls and LLM inputs.

    Pass it to any LangChain chain or agent via the callbacks parameter.
    Raises ToolException on BLOCK decisions so the agent can handle it gracefully.

    Example usage:
        from acf import Firewall
        from acf.adapters.langchain import FirewallCallbackHandler

        firewall = Firewall()
        handler = FirewallCallbackHandler(firewall)

        chain.invoke({"input": user_input}, config={"callbacks": [handler]})
    """

    def __init__(self, firewall: Firewall) -> None:
        super().__init__()
        self._firewall = firewall

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Intercept tool calls before execution."""
        tool_name = serialized.get("name", "unknown")
        result = self._firewall.on_tool_call(tool_name, {"input": input_str})
        if result == Decision.BLOCK:
            raise ToolException(
                f"Tool call '{tool_name}' blocked by ACF firewall policy."
            )

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Intercept LLM inputs before the model is called."""
        for prompt in prompts:
            result = self._firewall.on_prompt(prompt)
            if result == Decision.BLOCK:
                raise ToolException(
                    "LLM input blocked by ACF firewall policy."
                )