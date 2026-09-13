# AgentDojo scaffold (WIP)

Scaffold for running [AgentDojo](https://github.com/ethz-spylab/agentdojo) as
the model-in-the-loop benchmark referenced throughout `evaluation.tex`'s
`%% TODO before submission` markers (End-to-End Attack Success, Utility
Preservation, Contribution of Multi-Surface Coverage, Attribution Between
Detection and Authorisation).

**Division of labor**: this scaffold defines the condition registry, the
AgentDojo pipeline-splice point, and a runner CLI. Wiring each condition's
actual ACF firewall calls (`Firewall.on_prompt` / `on_context` /
`on_tool_call`) and building the paper's result tables is explicitly out of
scope here — every extension point below raises `NotImplementedError` with a
pointer back to this file until that lands.

## Install

```sh
pip install agentdojo          # pins to 0.1.35 as of this scaffold, see manifest.json
pip install -e sdk/python       # the ACF SDK itself
```

Needs Python >=3.10. Provider credentials (e.g. `OPENAI_API_KEY`) are only
required once you actually run a condition against a real model — every
offline test and the C1/C3/C4/C5 "not wired yet" CLI path works without one.

`manifest.json` in this folder pins the exact AgentDojo version, license, and
the full list of task suites/attacks this scaffold was checked against —
verified by installing the real package into a clean venv and inspecting its
source (`inspect.getsource`/`inspect.signature`), not from memory or docs
alone. It's deliberately separate from `../manifest.json`, which is owned by
the InjecAgent/PINT runner's own re-pin workflow.

## What AgentDojo actually looks like (verified against agentdojo==0.1.35)

- Four task suites: `banking`, `slack`, `travel`, `workspace`. Default
  benchmark version `v1.2.2`.
- Attacks are named strings loaded via
  `agentdojo.attacks.attack_registry.load_attack(name, suite, pipeline)` —
  see `manifest.json` for the full list (`important_instructions`,
  `tool_knowledge`, `injecagent`, several DoS variants, etc.).
- A custom agent/defense is any `agentdojo.agent_pipeline.BasePipelineElement`
  subclass implementing:
  ```python
  def query(self, query, runtime, env=EmptyEnv(), messages=(), extra_args={}) \
      -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]: ...
  ```
- `AgentPipeline(elements)` just runs `.query()` on each element in sequence,
  threading the returned tuple forward. `AgentPipeline.from_config()` builds
  one from a `PipelineConfig`, but its `defense=` field only accepts a name
  from AgentDojo's own fixed `DEFENSES` list (`tool_filter`,
  `transformers_pi_detector`, `repeat_user_prompt`,
  `spotlighting_with_delimiting`) — a custom defense like ACF can't go through
  that field, it raises `ValueError("Invalid defense name")`.
- So a custom defense has to be spliced into a manually-assembled element
  list instead. Reading `AgentPipeline.from_config`'s own source for its
  `transformers_pi_detector` case shows the exact splice point AgentDojo uses
  for a defense that inspects tool output before it goes back to the model:
  ```python
  tools_loop = ToolsExecutionLoop([ToolsExecutor(tool_output_formatter),
                                    <DEFENSE ELEMENT HERE>,
                                    llm])
  pipeline = AgentPipeline([system_message_component, init_query_component,
                            llm, tools_loop])
  ```
  That's the `on_context` / `on_tool_call` enforcement point. An `on_prompt`
  element belongs earlier, between `init_query_component` and `llm`:
  ```python
  AgentPipeline([system_message_component, init_query_component,
                 <ON_PROMPT ELEMENT HERE>, llm, tools_loop])
  ```
- Per-task results come back as a `SuiteResults` dict with
  `utility_results`, `security_results` (keyed by `(user_task_id,
  injection_task_id)`), and `injection_tasks_utility_results` — structured
  data, not just printed output. `security_results[k] is False` means the
  attack succeeded for that pair.

## Conditions (C0-C5)

Defined in `conditions.py`, inferred from `evaluation.tex`'s own wording —
not yet agreed with the team, adjust freely:

| Condition | ACF hooks active | Source line in evaluation.tex |
|---|---|---|
| C0 | none (undefended baseline) | "run AgentDojo for C0 and C5" |
| C1 | `on_prompt` | "compare C1 prompt-only enforcement with C5 full ACF" |
| C3 | `on_prompt`, `on_context` | "the 2 layers" — read as content detection vs tool authorisation |
| C4 | `on_tool_call` | ditto — tool authorisation layer only |
| C5 | `on_prompt`, `on_context`, `on_tool_call` | "full ACF" |

C2 is intentionally absent — `evaluation.tex` never names it, so nothing is
invented to fill the gap.

## Files

- `conditions.py` — the `CONDITIONS` registry above. `CONDITIONS["C0"].build_defense()`
  returns `None`; every other condition's `build_defense()` raises
  `NotImplementedError` until its ACF pipeline element is wired.
- `acf_pipeline.py` — `ACFPipelineElement(BasePipelineElement)` (one instance
  per active hook; `.query()` is a stub) and `build_pipeline(condition, llm)`,
  which fully assembles a real `AgentPipeline` for C0 today and raises
  `NotImplementedError` for C1/C3/C4/C5 before ever touching a provider
  client (so the "not wired" path works with no API key set).
- `run_agentdojo.py` — CLI: `--condition --suite --attack --model
  [--benchmark-version] [--user-tasks ...] [--out]`. Writes a JSON result
  record; for an unwired condition the record has `"status": "not_wired"`
  and a `"detail"` message, exit code 1. For C0 it actually calls
  `agentdojo.benchmark.benchmark_suite_with_injections` and records
  `utility_rate` / `security_rate` / `attack_success_rate` alongside the raw
  per-task results.
- `test_scaffold.py` — offline tests (no network, no API keys): condition
  registry shape, `ACFPipelineElement` construction/stub behaviour, and that
  `build_pipeline` assembles a real `AgentPipeline` for C0 using a dummy
  in-process LLM stand-in. Run with:
  ```sh
  python3 -m pytest benchmarks/agentdojo/test_scaffold.py -v
  ```

## What hasn't been done

No live AgentDojo run against a real model has been made from this
scaffold — that needs paid API credentials this pass didn't spend. C0 is the
only condition that will actually run today; everything else needs its ACF
wiring first. No result tables exist yet.
