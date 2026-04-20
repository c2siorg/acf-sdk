"""
FirewallNode — optional LangGraph node wrapper.

Wraps a Firewall instance as a LangGraph node that can be inserted into a
StateGraph. Fires on_prompt or on_context depending on configuration, and
raises NodeInterrupt on BLOCK decisions.

Import is guarded: importing this module without langgraph installed raises
ImportError with a helpful message (langgraph is not a required dependency).

Usage:
    from acf.firewall import Firewall
    from acf.adapters.langgraph import FirewallNode

    fw = Firewall(hmac_key=b"...")
    node = FirewallNode(fw)

    # In a StateGraph:
    graph.add_node("firewall", node.prompt_guard)
    graph.add_edge("input", "firewall")
    graph.add_edge("firewall", "llm")
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

try:
    from langgraph.errors import NodeInterrupt
except ImportError:
    raise ImportError(
        "langgraph is required to use the LangGraph adapter. "
        "Install it with: pip install langgraph"
    )

from ..firewall import Firewall
from ..models import Decision, SanitiseResult


class FirewallNode:
    """LangGraph node that enforces ACF policies at agent execution points.

    This node wraps the four v1 hooks (on_prompt, on_context, on_tool_call,
    on_memory) as LangGraph-compatible functions that can be inserted into
    a StateGraph.

    On BLOCK: raises NodeInterrupt to halt the graph execution.
    On SANITISE: replaces the content in the state with sanitised version.
    On ALLOW: passes the state through unchanged.

    Args:
        firewall: A configured Firewall instance.
    """

    def __init__(self, firewall: Firewall) -> None:
        self._fw = firewall

    def prompt_guard(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Guard node for user prompts.

        Reads the latest message from state["messages"], evaluates it
        via on_prompt, and either allows, sanitises, or blocks.

        Expected state keys:
            messages: list of message dicts with "content" and "role" keys.
        """
        messages = state.get("messages", [])
        if not messages:
            return state

        last_msg = messages[-1]
        content = (
            last_msg.get("content", "")
            if isinstance(last_msg, dict)
            else str(last_msg)
        )

        if not content:
            return state

        result = self._fw.on_prompt(content)

        if isinstance(result, SanitiseResult):
            # Replace last message content with sanitised version
            updated_messages = list(messages)
            if isinstance(last_msg, dict):
                updated_messages[-1] = {
                    **last_msg,
                    "content": result.sanitised_text or "",
                }
            return {**state, "messages": updated_messages}

        if result == Decision.BLOCK:
            raise NodeInterrupt(
                f"ACF Firewall blocked prompt: content flagged by on_prompt hook"
            )

        # ALLOW — pass through unchanged
        return state

    def context_guard(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Guard node for RAG context chunks.

        Reads context from state["context"] (list of strings),
        evaluates each chunk via on_context, filters blocked chunks,
        and replaces sanitised chunks.

        Expected state keys:
            context: list of strings (RAG chunks).
        """
        chunks = state.get("context", [])
        if not chunks:
            return state

        results = self._fw.on_context(chunks)
        filtered_chunks: List[str] = []

        for chunk_result in results:
            if chunk_result.decision == Decision.BLOCK:
                # Drop blocked chunks silently
                continue
            elif chunk_result.decision == Decision.SANITISE and chunk_result.sanitised_text:
                filtered_chunks.append(chunk_result.sanitised_text)
            else:
                filtered_chunks.append(chunk_result.original)

        return {**state, "context": filtered_chunks}

    def tool_guard(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Guard node for tool calls.

        Reads tool call from state["tool_call"] with keys "name" and "params".
        Evaluates via on_tool_call.

        Expected state keys:
            tool_call: dict with "name" (str) and "params" (dict).
        """
        tool_call = state.get("tool_call")
        if not tool_call:
            return state

        name = tool_call.get("name", "")
        params = tool_call.get("params", {})

        result = self._fw.on_tool_call(name, params)

        if isinstance(result, SanitiseResult):
            return state  # Allow with sanitised params handled by sidecar

        if result == Decision.BLOCK:
            raise NodeInterrupt(
                f"ACF Firewall blocked tool call: {name}"
            )

        return state

    def memory_guard(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Guard node for memory writes.

        Reads memory operation from state["memory_op"] with keys
        "key", "value", and optional "op" (default: "write").

        Expected state keys:
            memory_op: dict with "key" (str), "value" (str), "op" (str).
        """
        memory_op = state.get("memory_op")
        if not memory_op:
            return state

        key = memory_op.get("key", "")
        value = memory_op.get("value", "")
        op = memory_op.get("op", "write")

        result = self._fw.on_memory(key, value, op)

        if isinstance(result, SanitiseResult):
            return state

        if result == Decision.BLOCK:
            raise NodeInterrupt(
                f"ACF Firewall blocked memory {op}: key={key}"
            )

        return state
