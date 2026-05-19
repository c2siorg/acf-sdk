"""
FirewallNode — drop-in node for LangGraph.

Wraps a Firewall in a node you can insert anywhere in a StateGraph. Picks one
of the four hooks (on_prompt, on_context, on_tool_call, on_memory) and runs
it on whatever value you point it at in state.

If the firewall says BLOCK, the node raises NodeInterrupt — the graph halts.
If it says SANITISE, the node writes the cleaned value back to state.
If it says ALLOW, nothing changes.

langgraph is not a required dependency. Importing this module without it
raises ImportError with a useful message.
"""
from __future__ import annotations

from typing import Any, Callable, Literal, Optional

try:
    from langgraph.errors import NodeInterrupt
except ImportError as exc:
    raise ImportError(
        "FirewallNode requires langgraph. Install with: pip install langgraph"
    ) from exc

from ..firewall import Firewall
from ..models import Decision, SanitiseResult, ChunkResult


HookType = Literal["on_prompt", "on_context", "on_tool_call", "on_memory"]


class FirewallNode:
    """A LangGraph node that runs a firewall check on a value in state.

    Example:
        from langgraph.graph import StateGraph
        from acf import Firewall
        from acf.adapters.langgraph import FirewallNode

        fw = Firewall()

        graph = StateGraph(MyState)
        graph.add_node("prompt_guard", FirewallNode(
            firewall=fw,
            hook="on_prompt",
            input_key="user_message",
        ))

    Args:
        firewall:   The Firewall instance to use.
        hook:       Which hook to run. One of on_prompt, on_context,
                    on_tool_call, on_memory.
        input_key:  Where to read the value from in state.
        output_key: Where to write the result back. Defaults to input_key.
        on_block:   Optional callback (state, decision) -> None. Runs right
                    before NodeInterrupt is raised. Handy for logging.

    Raises:
        NodeInterrupt: On a BLOCK decision.
    """

    def __init__(
        self,
        firewall: Firewall,
        hook: HookType,
        input_key: str,
        output_key: Optional[str] = None,
        on_block: Optional[Callable[[dict, Decision], None]] = None,
    ) -> None:
        if hook not in ("on_prompt", "on_context", "on_tool_call", "on_memory"):
            raise ValueError(
                f"Invalid hook {hook!r}. Must be one of: "
                "on_prompt, on_context, on_tool_call, on_memory"
            )
        self._firewall = firewall
        self._hook = hook
        self._input_key = input_key
        self._output_key = output_key or input_key
        self._on_block = on_block

    def __call__(self, state: dict[str, Any]) -> dict[str, Any]:
        """Run the firewall check on the configured state key."""
        if self._input_key not in state:
            raise KeyError(
                f"FirewallNode: state is missing required key {self._input_key!r}"
            )

        value = state[self._input_key]
        decision = self._dispatch(value)

        # Blocked — let the caller know if they want, then halt the graph.
        if decision == Decision.BLOCK:
            if self._on_block is not None:
                self._on_block(state, decision)
            raise NodeInterrupt(
                f"FirewallNode blocked input at hook {self._hook}"
            )

        # Sanitised — swap the cleaned value back into state.
        if isinstance(decision, SanitiseResult):
            return {self._output_key: decision.sanitised_text}

        # on_context returns a list of per-chunk results — handled separately.
        if self._hook == "on_context" and isinstance(decision, list):
            return self._handle_context_result(decision)

        # Allowed — nothing to update.
        return {}

    def _dispatch(self, value: Any) -> Any:
        """Call the right hook on the firewall with the value from state."""
        if self._hook == "on_prompt":
            if not isinstance(value, str):
                raise TypeError(
                    f"on_prompt expects str, got {type(value).__name__}"
                )
            return self._firewall.on_prompt(value)

        if self._hook == "on_context":
            if not isinstance(value, list):
                raise TypeError(
                    f"on_context expects list[str], got {type(value).__name__}"
                )
            return self._firewall.on_context(value)

        if self._hook == "on_tool_call":
            if not isinstance(value, dict) or "name" not in value:
                raise TypeError(
                    "on_tool_call expects dict with 'name' and 'params' keys"
                )
            return self._firewall.on_tool_call(
                name=value["name"],
                params=value.get("params", {}),
            )

        if self._hook == "on_memory":
            if not isinstance(value, dict) or "key" not in value or "value" not in value:
                raise TypeError(
                    "on_memory expects dict with 'key', 'value', and 'op' keys"
                )
            return self._firewall.on_memory(
                key=value["key"],
                value=value["value"],
                op=value.get("op", "write"),
            )

        raise RuntimeError(f"Unreachable hook: {self._hook}")

    def _handle_context_result(
        self, results: list[ChunkResult]
    ) -> dict[str, Any]:
        """Drop blocked chunks, swap in sanitised text where present, keep the rest."""
        kept: list[str] = []
        for r in results:
            if r.decision == Decision.BLOCK:
                # Blocked chunk — drop it without halting the graph.
                continue
            if r.decision == Decision.SANITISE and r.sanitised_text is not None:
                kept.append(r.sanitised_text)
            else:
                kept.append(r.original)
        return {self._output_key: kept}