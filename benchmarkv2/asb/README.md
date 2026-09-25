# Agent Security Bench (ASB) with ACF enforcement

**Status: scaffold.** The plumbing works and `--dry-run` runs today. Two
functions in `run_asb.py` still need the upstream adapter: `load_cases` and
`run_case`. Both raise `NotImplementedError` naming what to write.

## What it measures and why

ASB is the broad-coverage benchmark. It spans five attack classes over many
agents and tools:

| ASB attack class | What it tampers with | ACF hook expected to stop it |
|---|---|---|
| Direct prompt injection | the user prompt | `on_prompt` |
| Observation prompt injection | tool output the agent reads | `on_context` |
| Memory poisoning | plans written into agent memory | `on_memory` |
| Plan-of-thought backdoor | a trigger in the input | `on_prompt` |
| Mixed | several channels at once | multiple |

ACF mediates prompts, retrieved content, tool calls and memory as separate
enforcement points, and this is the only planned benchmark that exercises all
four. Its value for the paper is therefore per-hook attribution: which
enforcement point actually stops which attack class. The runner records where
each attack was intercepted, so a result that disagrees with the table above is
a finding, not a harness bug. It backs §eval-asb.

Upstream reports ASR, refuse rate (RR), no-attack performance (PNA) and, for
detection defences, false negative and positive rates.

## Two integration modes

Decide this before implementing, and state it in the paper:

- **`hooks`** replays each attack's text and tool calls through the ACF hooks
  with no agent. Cheap, deterministic, no API spend, but it measures detection
  and authorisation, not agent attack success. This is what `benchmarks/` does
  for InjecAgent.
- **`agent`** drives ASB's own agent loop with ACF between the agent and its
  tools and memory. This is what the paper's ASR numbers need, and it costs
  model calls.

`--mode` selects one, and the choice is recorded in the run's provenance.

## Arms

Shared with the other benchmarkv2 benchmarks, defined in
[`../common/harness.py`](../common/harness.py): `none`, `gate-global`,
`gate-task`, `detect`, `full-global`, `full-task`. See
[`../agentdojo/README.md`](../agentdojo/README.md) for what the allowlist
scopes mean and why both are reported.

## Prerequisites

- Go, for building the sidecar, and Python 3.10+. Upstream documents Python
  3.11, and one environment can host both.
- A clone of ASB checked out at the pinned commit, plus its own requirements:

```sh
git clone https://github.com/agiresearch/ASB benchmarkv2/asb/upstream/ASB
git -C benchmarkv2/asb/upstream/ASB checkout <pinned commit>
pip install -r benchmarkv2/asb/upstream/ASB/requirements.txt
```

- API keys for closed models, or `ollama` for the open-weights backbones, only
  in `agent` mode.

## Pin the commit first

`manifest.json` ships with `commit` set to `null`, and the runner refuses to run
until it holds a full 40-character SHA and the clone is checked out at it. Add
every attack-case and agent-definition file the adapter reads to `files` with
its SHA-256, so a run cannot score against content that drifted. ASB is used
from a clone rather than a package, so the commit is the only version
identifier.

## Running

```sh
# 1. Sidecar side only: builds the sidecar, starts it, runs the preflight
#    controls, makes no model calls or upstream calls. Run this first.
python benchmarkv2/asb/run_asb.py --dry-run --build-sidecar

# 2. Model-free replay of one attack class.
python benchmarkv2/asb/run_asb.py --mode hooks --attack-types observation_prompt_injection --limit 20

# 3. Live agent, the arms the paper reports.
python benchmarkv2/asb/run_asb.py --mode agent --arms none,detect,full-global --limit 50
```

Upstream's own entrypoints, for reference while writing the adapter:

```sh
python scripts/agent_attack.py --cfg_path config/DPI.yml   # also OPI.yml, MP.yml, mixed.yml
python scripts/agent_attack_pot.py
```

## Implementing the adapter

1. **`load_cases`** — read the cases for one attack class from the pinned
   clone, and hash every file read into the run's provenance.
2. **`run_case`** — run one case with ACF in the loop. The ACF calls are fixed:
   user prompts through `firewall.on_prompt`, observations through
   `harness.screen_observation`, tool calls through `harness.gate_tool_call`,
   memory reads and writes through `firewall.on_memory`. Record which hook
   first returned BLOCK or SANITISE as `intercepted_at`; that field is the
   reason this benchmark is in the paper.

Scoring, summaries and provenance are already written and covered by tests.

## Outputs

`results/<UTC timestamp>-<mode>-<model>/`:

- `records.jsonl` — one line per (attack class, agent, case, arm) with every
  ACF verdict and the interception point
- `summary.json` — scores per arm and attack class, sidecar preflights,
  provenance
- `summary.md` — per arm, then per attack class with expected versus actual
  interception point
- `work/` — the generated sidecar configs and logs

## Tests

```sh
python -m pytest benchmarkv2/asb benchmarkv2/common
```

The tests cover scoring, the interception breakdown, the clone and pin checks,
and the report. One test asserts both adapters still raise
`NotImplementedError`; replace it with tests of the real behaviour once they are
written.
