"""ACF firewall spliced into an AgentDojo pipeline.

Verified against agentdojo==0.1.35 by importing the real package and
inspecting AgentPipeline.from_config's source directly (not from memory).
The insertion point that from_config uses for its own "transformers_pi_detector"
defense is:

    tools_loop = ToolsExecutionLoop([ToolsExecutor(tool_output_formatter),
                                      <DEFENSE ELEMENT HERE>,
                                      llm])
    pipeline = AgentPipeline([system_message_component, init_query_component,
                              llm, tools_loop])

That is the on_context / on_tool_call enforcement point: it sees tool
results before they go back to the LLM. An on_prompt element belongs earlier
in the outer list, between init_query_component and llm:

    AgentPipeline([system_message_component, init_query_component,
                   <ON_PROMPT ELEMENT HERE>, llm, tools_loop])

`PipelineConfig.defense` only accepts a name from agentdojo's own fixed
DEFENSES list (raises ValueError otherwise), so a custom defense can't go
through from_config's `defense=` field -- the pipeline has to be assembled
by hand as above. build_pipeline() below does that assembly; it works today
for C0 (no ACF element at all) and raises NotImplementedError for the other
conditions until their ACF wiring lands.

Division of labor: this file defines the shape of the integration --
ACFPipelineElement's interface and where it splices in. Which ACF hook
fires on which AgentDojo pipeline event, and how a BLOCK/SANITISE decision
translates into the tuple query() must return, is deliberately left open --
see conditions.py's per-condition acf_hooks and the NotImplementedError
messages raised from there.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Sequence

_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, ToolsExecutor
from agentdojo.functions_runtime import Env, EmptyEnv, FunctionsRuntime
from agentdojo.types import ChatMessage

from acf import Firewall

from conditions import CONDITIONS, Condition  # noqa: E402


class ACFPipelineElement(BasePipelineElement):
    """Wraps an ACF Firewall instance as an AgentDojo pipeline element.

    One instance is meant to cover exactly one ACF hook (on_prompt,
    on_context, or on_tool_call) -- construct one per active hook for a
    condition and splice each at its matching point (see module docstring),
    rather than one element trying to run every hook.
    """

    name = "acf_firewall"

    def __init__(self, firewall: Firewall, hook: str) -> None:
        if hook not in ("on_prompt", "on_context", "on_tool_call"):
            raise ValueError(f"Unknown ACF hook: {hook!r}")
        self._firewall = firewall
        self._hook = hook

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = (),
        extra_args: dict[str, Any] | None = None,
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict[str, Any]]:
        raise NotImplementedError(
            f"ACFPipelineElement(hook={self._hook!r}).query is a scaffold "
            "stub. Call self._firewall.<hook>(...) with the right piece of "
            "`query`/`messages`/`extra_args`, translate a BLOCK/SANITISE "
            "Decision into this method's return tuple (e.g. raise to abort "
            "the agent turn on BLOCK, or rewrite the outgoing text on "
            "SANITISE), and return ALLOW cases unchanged. "
            "See benchmarks/agentdojo/README.md."
        )


def build_pipeline(condition: Condition, llm: str | BasePipelineElement) -> AgentPipeline:
    """Assemble an AgentPipeline for one condition.

    llm may be a real model name string (needs the matching provider's API
    key set, e.g. OPENAI_API_KEY) or any BasePipelineElement stand-in, which
    is what the offline tests in test_scaffold.py use.

    Only C0 (no ACF element) is fully wired today. Every other condition
    calls condition.build_defense(), which raises NotImplementedError until
    someone wires its ACFPipelineElement(s) in -- see conditions.py.
    """
    if condition.name != "C0":
        # Any condition beyond C0 needs at least one wired ACFPipelineElement.
        # Check before touching the LLM/provider client at all, so an unwired
        # condition reports "not wired" even with no API key configured,
        # rather than failing on a missing credential first.
        condition.build_defense()
        raise AssertionError(
            f"condition.build_defense() for {condition.name!r} returned "
            "instead of raising -- build_pipeline needs updating to "
            "actually splice the returned element(s) in once wiring lands."
        )

    from agentdojo.agent_pipeline.agent_pipeline import load_system_message
    from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM
    from agentdojo.agent_pipeline.tool_execution import tool_result_to_str

    system_message_component = SystemMessage(load_system_message(None))
    init_query_component = InitQuery()

    if isinstance(llm, str):
        import openai

        llm_element: BasePipelineElement = OpenAILLM(openai.OpenAI(), llm)
    else:
        llm_element = llm

    tools_loop = ToolsExecutionLoop([ToolsExecutor(tool_result_to_str), llm_element])
    pipeline = AgentPipeline(
        [system_message_component, init_query_component, llm_element, tools_loop]
    )
    pipeline.name = f"agentdojo-{condition.name}"
    return pipeline


__all__ = ["ACFPipelineElement", "build_pipeline", "CONDITIONS"]
