"""AgentDojo evaluation conditions (C0-C5).

Scaffold only. Condition semantics below are inferred from the paper's
evaluation.tex TODOs, not yet agreed with the team -- adjust freely:

  - "run AgentDojo for C0 and C5" (End-to-End Attack Success)
  - "compare C1 prompt-only enforcement with C5 full ACF"
    (Contribution of Multi-Surface Coverage)
  - "The planned AgentDojo C3, C4, and C5 runs are needed to measure the 2
    layers under the same model trajectories and action oracle"
    (Attribution Between Detection and Authorisation) -- that section is
    explicitly about "the detector replay evaluates injected content"
    (on_context, via InjecAgent's tool-response replay) vs "the
    authorisation replay evaluates the tool names" (on_tool_call). on_prompt
    never comes up there -- it's PINT's own separate on_prompt replay,
    already covered by C1. So C3 below is on_context alone (the content
    path from that section), not on_prompt+on_context.

C2 is intentionally absent: evaluation.tex never names it, so no condition
is invented to fill the gap.

Division of labor: this file defines the condition registry and the
extension point (`build_defense`). Wiring each condition's actual ACF
pipeline element is out of scope here -- see acf_pipeline.py.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement


@dataclass(frozen=True)
class Condition:
    """One evaluation condition for the AgentDojo comparison.

    acf_hooks lists which ACF hooks are active for this condition, in the
    order they'd fire in an AgentDojo pipeline. An empty tuple means no ACF
    hook runs at all (the undefended baseline).
    """

    name: str
    description: str
    acf_hooks: tuple[str, ...]
    build_defense: Callable[[], BasePipelineElement | None]


def _not_wired(name: str, hooks: tuple[str, ...]) -> Callable[[], BasePipelineElement | None]:
    def _raise() -> BasePipelineElement | None:
        raise NotImplementedError(
            f"Condition {name!r} (hooks={hooks}) has no ACF pipeline element "
            "wired yet. See benchmarks/agentdojo/acf_pipeline.py and "
            "benchmarks/agentdojo/README.md."
        )

    return _raise


CONDITIONS: dict[str, Condition] = {
    "C0": Condition(
        name="C0",
        description="Undefended baseline agent. No ACF hook runs.",
        acf_hooks=(),
        build_defense=lambda: None,
    ),
    "C1": Condition(
        name="C1",
        description="Prompt-only enforcement: on_prompt runs before the "
        "agent's first turn, nothing else.",
        acf_hooks=("on_prompt",),
        build_defense=_not_wired("C1", ("on_prompt",)),
    ),
    "C3": Condition(
        name="C3",
        description="Content path only: on_context, no tool authorisation "
        "and no on_prompt (that's C1's territory).",
        acf_hooks=("on_context",),
        build_defense=_not_wired("C3", ("on_context",)),
    ),
    "C4": Condition(
        name="C4",
        description="Tool-authorisation layer only: on_tool_call, no content "
        "detection.",
        acf_hooks=("on_tool_call",),
        build_defense=_not_wired("C4", ("on_tool_call",)),
    ),
    "C5": Condition(
        name="C5",
        description="Full ACF: on_prompt, on_context, and on_tool_call "
        "together.",
        acf_hooks=("on_prompt", "on_context", "on_tool_call"),
        build_defense=_not_wired("C5", ("on_prompt", "on_context", "on_tool_call")),
    ),
}
