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
needed for a cloud model. A local model works with no API key at all: point
`--model local` (or `--model vllm_parsed`) at an OpenAI-compatible server on
`localhost` via `--model-id <model served>` and, if the server isn't on port
8000, the `LOCAL_LLM_PORT` env var. `build_pipeline`/`get_llm` resolve
`"local"`/`"vllm_parsed"` the same way `AgentPipeline.from_config` does —
verified end to end against a real local Ollama server (see "Live-tested
against a local model" below). Every offline test and the C1/C3/C4/C5 "not
wired yet" CLI path also works without any credentials.

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
| C3 | `on_context` | "the 2 layers" — that section is specifically "the detector replay evaluates injected content" (on_context) vs "the authorisation replay evaluates the tool names" (on_tool_call); on_prompt never comes up there, it's PINT's own separate replay, already covered by C1 |
| C4 | `on_tool_call` | ditto — tool authorisation layer only |
| C5 | `on_prompt`, `on_context`, `on_tool_call` | "full ACF" |

C2 is intentionally absent — `evaluation.tex` never names it, so nothing is
invented to fill the gap.

## Files

- `conditions.py` — the `CONDITIONS` registry above. `CONDITIONS["C0"].build_defense()`
  returns `None`; every other condition's `build_defense()` raises
  `NotImplementedError` until its ACF pipeline element is wired.
- `acf_pipeline.py` — `ACFPipelineElement(BasePipelineElement)` (one instance
  per active hook; `.query()` is a stub) and
  `build_pipeline(condition, llm, model_id=None)`, which fully assembles a
  real `AgentPipeline` for C0 today and raises `NotImplementedError` for
  C1/C3/C4/C5 before ever touching a provider client (so the "not wired"
  path works with no API key set). `llm` takes a `ModelsEnum` string (cloud),
  `"local"`/`"vllm_parsed"` (local server, pair with `model_id`), or a
  `BasePipelineElement` instance directly.
- `run_agentdojo.py` — CLI: `--condition --suite --attack --model
  [--model-id] [--benchmark-version] [--user-tasks ...] [--out]`. Writes a
  JSON result record; for an unwired condition the record has
  `"status": "not_wired"` and a `"detail"` message, exit code 1. For C0 it
  actually calls `agentdojo.benchmark.benchmark_suite_with_injections`
  (wrapped in `with OutputLogger(logdir=None):`, see "Live-tested against a
  local model" below) and records `utility_rate` / `security_rate` /
  `attack_success_rate` alongside the raw per-task results.
- `test_scaffold.py` — offline tests (no network, no API keys): condition
  registry shape, `ACFPipelineElement` construction/stub behaviour, and that
  `build_pipeline` assembles a real `AgentPipeline` for C0 using a dummy
  in-process LLM stand-in. Run with:
  ```sh
  python3 -m pytest benchmarks/agentdojo/test_scaffold.py -v
  ```

## Live-tested against a local model

C0 was run end to end against a real local model at zero cost: Ollama
(`ollama serve`) on `localhost:11434` serving `llama3.2:latest`, hit through
its OpenAI-compatible API (`provider="local"`, no API key). Two real bugs
turned up doing this, both fixed in this scaffold:

1. `agentdojo.benchmark.benchmark_suite_with_injections` (and the lower-level
   `run_task_with(out)_injection_tasks` it calls) reads `Logger.get()` to
   build a `TraceLogger`, but never opens a logger context itself. With
   nothing entered, `Logger.get()` falls back to a bare `NullLogger()` whose
   `.logdir` was never set (its own `__enter__` sets `.logdir` but — unlike
   the base `Logger.__enter__` — doesn't push onto `LOGGER_STACK`, so
   `Logger.get()` never sees it even inside `with NullLogger():`). Fixed by
   wrapping the call in `with OutputLogger(logdir=None):` instead, which
   does push correctly via the inherited base `__enter__`/`__exit__`.
2. Attacks that name-drop the model (`important_instructions` and its
   variants) call `get_model_name_from_pipeline(pipeline)`, which requires
   `pipeline.name` to contain one of `agentdojo.attacks.base_attacks.
   MODEL_NAMES`'s keys as a substring — a real model string, or literally
   `"local"`/`"vllm_parsed"`. A custom label like `"agentdojo-C0"` fails that
   lookup with a `ValueError`. Fixed by keeping the raw model identifier in
   `pipeline.name` (`f"{llm_name}-{condition.name}"`, e.g. `"local-C0"`).

With both fixed, a full run completed cleanly:

```sh
export LOCAL_LLM_PORT=11434
python3 benchmarks/agentdojo/run_agentdojo.py \
  --condition C0 --suite banking --attack important_instructions \
  --model local --model-id llama3.2:latest --user-tasks user_task_0 \
  --out /tmp/c0_result.json
```

`"status": "completed"`, all 9 `important_instructions` injection tasks run
against `user_task_0`, JSON result written with per-pair `utility_results`/
`security_results` plus aggregate rates. `utility_rate` and `security_rate`
both came out `0.0` for this run — llama3.2 (2GB, no fine-tuning for this
kind of agentic task) neither solved the banking task correctly nor resisted
the injection, which is unsurprising for a small local model and an
undefended C0 baseline; it's not evidence about ACF, since no ACF hook runs
in C0. Confirms the scaffold's plumbing works end to end, not that any
particular model/attack pair is a meaningful result.

## What hasn't been done

No run against a paid cloud model. C1/C3/C4/C5 still need their ACF pipeline
elements wired before they'll run against any model, local or cloud. No
result tables exist yet.
