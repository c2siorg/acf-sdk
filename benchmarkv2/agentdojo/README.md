# AgentDojo with ACF in the agent loop

**Status: scaffold.** The plumbing works and `--dry-run` runs today. Three
functions in `run_agentdojo.py` still need the upstream adapter:
`available_suites`, `build_pipeline` and `run_case`. Each raises
`NotImplementedError` naming what to write.

## What it measures and why

AgentDojo scores both sides of a defence on the same tasks:

- **benign utility** — the agent finishes the user's task with no attack present
- **utility under attack** — it still finishes the task while under attack
- **attack success rate (ASR)** — the injected task succeeds

Utility under attack is the number a detector-only evaluation cannot produce: a
firewall that blocks everything scores a perfect ASR and useless utility. This
is also the benchmark CaMeL and Progent report on, so it is where ACF can be
compared with prior system-level defences. It backs §eval-agentdojo.

## Arms

Arms are shared across the benchmarkv2 benchmarks and defined in
[`../common/harness.py`](../common/harness.py).

| Arm | `on_context` on tool results | `on_tool_call` on tool calls |
|---|---|---|
| `none` | no | no |
| `gate-global` | no | yes, allowlist = every tool in the suite |
| `gate-task` | no | yes, allowlist = only the task's own tools |
| `detect` | yes | no |
| `full-global` | yes | yes, global allowlist |
| `full-task` | yes | yes, task allowlist |

Report both allowlist scopes and say which is which. A global allowlist lets the
benchmark supply both the tasks and the permitted tool names, which flatters the
result. A task allowlist is least privilege, a stronger result, but it assumes
each task's tools are known in advance.

## Prerequisites

- Go, for building the sidecar, and Python 3.10+.
- `pip install 'agentdojo==<pinned version>'`. Add the `transformers` extra only
  if a run compares against upstream's own prompt-injection detector.
- An API key for the agent model, in the environment of the process that runs
  the command.
- The SDK's `[scanners]` extra, for `--semantic tfidf` or
  `--semantic sentence-transformer`.

## Pin the version first

`manifest.json` ships with `package.version` set to `null`, and the runner
refuses to run until it is pinned. Install the version you intend to measure,
put that exact string in `manifest.json`, and the runner then refuses to run
against any other install. Latest release seen upstream: 0.1.35 (2025-10-27).
Record the suites and the `--attack` value in the run's provenance, which the
runner does for you.

## Running

```sh
# 1. Sidecar side only: builds the sidecar, starts it, runs the preflight
#    controls, makes no model calls. Run this first.
python benchmarkv2/agentdojo/run_agentdojo.py --dry-run --build-sidecar

# 2. Pilot: a few user tasks on one suite, one attack, two arms.
python benchmarkv2/agentdojo/run_agentdojo.py --suites workspace --limit 5 --arms none,full-global

# 3. Full run: every suite, the arms the paper reports.
python benchmarkv2/agentdojo/run_agentdojo.py --arms none,detect,gate-global,full-global,full-task

# Lexical vs lexical+semantic detection
python benchmarkv2/agentdojo/run_agentdojo.py --arms detect,full-task --semantic tfidf
```

`--suites all` uses whatever the pinned install registers. Check the upstream
flags with `python -m agentdojo.scripts.benchmark --help`; its README documents
`--defense tool_filter` and `--attack tool_knowledge`.

## Implementing the adapter

1. **`available_suites`** — list the suites from the installed package instead
   of hard-coding them, so the recorded set matches the version measured.
2. **`build_pipeline`** — put ACF into the upstream pipeline. The ACF side is
   already decided: every tool result the agent is about to read goes through
   `harness.screen_observation(firewall, text)`, and every tool call the model
   chooses goes through `harness.gate_tool_call(firewall, name, params)` before
   it runs. ACF is a defence of the same kind as upstream's `--defense`
   options, so it belongs at the same point in the pipeline. Confirm the class
   names against the pinned version rather than trusting any list here; the
   upstream docs site renders with JavaScript and its README does not cover
   custom defences.
3. **`run_case`** — run one user task with and without an injection task, and
   fill in a record with the `RECORD_FIELDS` keys. Utility and attack success
   must come from the suite's own checks, evaluated **after** enforcement, so a
   tool call ACF blocked counts as an unsuccessful attack.

Scoring, summaries and provenance are already written and covered by tests, so
the adapter only has to produce records.

## Outputs

`results/<UTC timestamp>-<model>/`:

- `records.jsonl` — one line per (suite, user task, injection task, arm), with
  every ACF verdict
- `summary.json` — scores per arm and suite, sidecar preflights, provenance
  (commit, file and binary hashes, platform, versions)
- `summary.md` — the tables: per arm, then per suite
- `work/` — the generated sidecar configs and logs

## Tests

```sh
python -m pytest benchmarkv2/agentdojo benchmarkv2/common
```

The tests cover scoring, allowlist scope, the version check and the report. One
test asserts the three adapters still raise `NotImplementedError`; when you
implement them, that test should be replaced with tests of the real behaviour.
