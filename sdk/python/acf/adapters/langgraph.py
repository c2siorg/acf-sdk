"""
FirewallNode — optional LangGraph node wrapper.
Wraps a Firewall instance as a LangGraph node that can be inserted into a
StateGraph. Fires on_prompt or on_context depending on configuration, and
raises NodeInterrupt on BLOCK decisions.

Import is guarded: importing this module without langgraph installed raises
ImportError with a helpful message (langgraph is not a required dependency).
"""
from __future__ import annotations

from typing import Any

try:
    from langgraph.errors import NodeInterrupt
except ImportError as exc:
    raise ImportError(
        "langgraph is required to use FirewallNode. "
        "Install it with: pip install langgraph"
    ) from exc

from ..firewall import Firewall
from ..models import Decision, SanitiseResult


class FirewallNode:
    """LangGraph node that enforces ACF policy at each execution boundary.

    Insert it into a StateGraph as a node that runs before your agent node.
    On a BLOCK decision the node raises NodeInterrupt, halting the graph.
    On a SANITISE decision the node replaces the input with the scrubbed version.

    Example usage:
        from acf import Firewall
        from acf.adapters.langgraph import FirewallNode
        from langgraph.graph import StateGraph

        firewall = Firewall()
        fw_node = FirewallNode(firewall)

        graph = StateGraph(AgentState)
        graph.add_node("firewall", fw_node)
        graph.add_node("agent", your_agent_node)
        graph.add_edge("firewall", "agent")
    """

    def __init__(self, firewall: Firewall) -> None:
        self._firewall = firewall

    def __call__(self, state: dict[str, Any]) -> dict[str, Any]:
        """Evaluate the current agent state and return the (possibly sanitised) state.

        Checks the following state fields if present:
          - "messages": last message is treated as a user prompt (on_prompt)
          - "context" or "documents": treated as RAG chunks (on_context)

        Raises NodeInterrupt if any check returns BLOCK.
        """
        state = dict(state)

        # Check the latest user message
        messages = state.get("messages", [])
        if messages:
            last = messages[-1]
            text = last.content if hasattr(last, "content") else str(last)
            result = self._firewall.on_prompt(text)

            if result == Decision.BLOCK:
                raise NodeInterrupt("Input blocked by ACF firewall policy.")

            if isinstance(result, SanitiseResult) and result.sanitised_text:
                sanitised = list(messages)
                last_msg = sanitised[-1]
                if hasattr(last_msg, "content"):
                    last_msg = last_msg.__class__(content=result.sanitised_text)
                    sanitised[-1] = last_msg
                state["messages"] = sanitised

        # Check RAG context chunks
        chunks = state.get("context") or state.get("documents") or []
        if chunks:
            raw = [c.page_content if hasattr(c, "page_content") else str(c) for c in chunks]
            results = self._firewall.on_context(raw)

            safe_chunks = []
            for original_chunk, chunk_result in zip(chunks, results):
                if chunk_result.decision == Decision.BLOCK:
                    continue
                if chunk_result.sanitised_text is not None:
                    if hasattr(original_chunk, "page_content"):
                        original_chunk = original_chunk.__class__(
                            page_content=chunk_result.sanitised_text,
                            metadata=getattr(original_chunk, "metadata", {}),
                        )
                    else:
                        original_chunk = chunk_result.sanitised_text
                safe_chunks.append(original_chunk)

            key = "context" if "context" in state else "documents"
            state[key] = safe_chunks

        return state