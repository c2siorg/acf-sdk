# AgentDojo with ACF in the agent loop

The runner targets `agentdojo==0.1.35` and benchmark registry `v1.2.2`. It
enumerates suites and task IDs from that install, then runs benign and attacked
cases through AgentDojo's task evaluators after ACF enforcement.

## Metrics

- **Benign utility**: the user's task succeeds without an injection task.
- **Utility under attack**: the user's task succeeds with an injection task.
- **Attack success rate (ASR)**: the injection task succeeds. AgentDojo's
  evaluator supplies this for non-DoS attacks. Its DoS convention is
  `not utility`.

Errors are records, not benchmark outcomes, and are excluded from scores. The
runner stores exception types only, not exception messages or provider keys.
Model-free tests and `--dry-run` do not make model calls and produce no ASR.

## Enforcement arms

All 6 shared arms from [`../common/harness.py`](../common/harness.py) are
available:

| Arm | `on_context` on tool results | `on_tool_call` on tool calls |
|---|---|---|
| `none` | no | no |
| `detect` | yes | no |
| `gate-global` | no | yes, suite-wide tool allowlist |
| `gate-task` | no | yes, task-scoped tool allowlist |
| `full-global` | yes | yes, suite-wide tool allowlist |
| `full-task` | yes | yes, task-scoped tool allowlist |

Global arms use `suite.tools`. AgentDojo does not define task-authorized tool
sets, so task scopes are derived from each task's canonical `ground_truth`
calls. This is an oracle-derived scope, not an upstream authorization label.
`gate-task` and `full-task` fail clearly if a non-empty scope cannot be derived.
These scopes may exclude valid alternative tool sequences, so a blocked benign
case can reflect the oracle-derived scope rather than a malicious operation.

Tool calls pass through `gate_tool_call` immediately before execution. `BLOCK`
calls never execute. The shared helper returns only a verdict, so `SANITISE`
calls are also withheld and counted separately. The adapter never executes the
original parameters after a `SANITISE` verdict; sanitized-parameter execution
remains unsupported by the current shared contract.

Tool output and error text pass through `on_context` before returning to the
agent. `BLOCK`, unsupported content, or screening errors withhold the output
and clear the tool error. `SANITISE` returns only the sanitized observation.

## Model and upstream behavior

The default model remains the exact ID `gpt-4o-2024-08-06`. AgentDojo 0.1.35
does not list that checkpoint in `ModelsEnum`. The adapter builds the OpenAI
LLM with the exact requested ID and registers that ID in `MODEL_NAMES` with the
existing `GPT-4` attack-prompt family. The model sent to OpenAI is not changed
to `gpt-4o-2024-05-13`.

`gpt-4o-2024-11-20` is also supported explicitly. Results retain the selected
checkpoint; results from different checkpoints must be reported separately.

For DoS attacks, AgentDojo 0.1.35 evaluates against the suite's initial injection
task. Each record includes the requested and effective injection task IDs.
Direct `suite.run_task_with_pipeline` calls keep provider and context errors
separate from utility and security scores.

## Running

Requirements: Python 3.10+, Go for sidecar builds, the pinned AgentDojo package,
and provider configuration for live model runs. The runner does not write
provider keys to results.

Live runs default to a hard cap of 20 OpenAI request attempts. The runner
disables the OpenAI client's internal retries and counts each AgentDojo retry
against `--max-api-calls`. When the cap is reached, it stops without writing
scores and saves completed cases as `partial_records.jsonl`. The cap limits
request attempts, not tokens or currency, so check usage before raising it.
An ambient `OPENAI_BASE_URL` requires an explicit `--base-url` for live runs.
`--max-output-tokens` optionally caps each response. Both limits and returned
token usage are recorded. A truncated response can affect task completion, so
use the same output cap in every compared arm and disclose it.

For Azure OpenAI, set `AZURE_OPENAI_ENDPOINT` and `AZURE_OPENAI_API_KEY` in the
runner process, then pass `--azure-deployment <name>` and `--model <checkpoint>`.
Verify the deployment version before running. The deployment name is sent to
Azure; the checkpoint, deployment name, API version and response model IDs are
recorded in provenance. Credentials are omitted. The Azure API version is
`2024-10-21`.

AgentDojo 0.1.35 omits temperature when its configured value is `0.0`, so these
requests use the provider default. Provenance records that behavior. A paper run
that requires temperature `0.0` must fix that upstream behavior first.

```sh
# Sidecar preflight only, with no model calls
python benchmarkv2/agentdojo/run_agentdojo.py --dry-run --build-sidecar

# Small pilot
# 8 trajectories: 2 user tasks, 1 injection task, benign and attacked, 2 arms
python benchmarkv2/agentdojo/run_agentdojo.py --suites workspace --limit 2 --injection-limit 1 --arms none,full-global

# All 6 arms on every registered suite
python benchmarkv2/agentdojo/run_agentdojo.py --arms none,detect,gate-global,gate-task,full-global,full-task
```

`--suites all` uses the installed `v1.2.2` registry and checks it against the
suite list in `manifest.json`. `--limit` selects a stable numeric user-task
prefix per suite. `--injection-limit` optionally caps injection tasks per
suite; without it, all injection tasks run. DoS attacks already run only the
upstream effective task. Both limits are recorded in provenance. Task-scoped
arms may stop if task tools cannot be derived.

## Results and tests

Each run writes `records.jsonl`, `summary.json`, `summary.md`, and sidecar
work files under `results/<UTC timestamp>-<model>/`. Records include requested
and effective attack task IDs, arm allowlists, per-call verdicts, enforcement
counters, score outcomes, and error types.

Run model-free tests with:

```sh
python -m pytest -p no:cacheprovider benchmarkv2/agentdojo benchmarkv2/common -q
```
