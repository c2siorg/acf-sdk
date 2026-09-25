#!/usr/bin/env python3
"""Run AgentDojo with ACF enforcement inside the agent loop. SCAFFOLD.

AgentDojo is the security-and-utility benchmark: it scores whether the agent
still finishes the user's task (utility) and whether the injected task
succeeds (attack success rate), so it shows both sides of a defence. It backs
§eval-agentdojo in the paper.

What this file already does:

- pins the AgentDojo version and refuses to run against a different install
- builds the sidecar and starts one per tool allowlist, with preflight checks
- defines the arms, shared with the other benchmarks (see common/harness.py)
- scores records into benign utility, utility under attack and ASR, per suite
- writes records, summary.json and summary.md with full provenance

What is left to implement, marked TODO below:

1. `available_suites`  — enumerate the suites the pinned install registers.
2. `build_pipeline`    — wrap AgentDojo's agent pipeline so tool results pass
                         through `on_context` and tool calls through
                         `on_tool_call`. Upstream's own defences are selected
                         with `--defense`; ACF is a defence of the same kind, so
                         it belongs in the same place. The upstream class names
                         are deliberately not guessed here: check them against
                         the pinned version (`python -m agentdojo.scripts.benchmark
                         --help`, and the `agentdojo.agent_pipeline` module).
3. `run_case`          — run one user task, with and without an injection task,
                         and return a record with the fields in RECORD_FIELDS.

Until those exist, `--dry-run` still works and is worth running: it starts the
sidecars, runs the preflight controls and prints the plan, so the ACF half of
the harness is verified before any model spend.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import sys
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))  # benchmarkv2/ on the path, for `common`

from common import harness  # noqa: E402

MANIFEST_PATH = HERE / "manifest.json"
DEFAULT_BINARY = HERE / ".bin" / f"sidecar{harness.EXE}"
DEFAULT_RESULTS_DIR = HERE / "results"
DEFAULT_CACHE_DIR = HERE / "cache"
DEFAULT_MODEL = "gpt-4o-2024-08-06"
DEFAULT_ATTACK = "tool_knowledge"

# One record per (suite, user task, injection task, arm). `injection_task` is
# None for the benign run of a user task.
RECORD_FIELDS = (
    "suite", "user_task", "injection_task", "arm", "utility", "attack_succeeded",
    "blocked_calls", "altered_observations", "legitimate_call_verdicts", "error",
)


# ── upstream ─────────────────────────────────────────────────────────────────


def installed_version() -> str | None:
    try:
        return importlib.metadata.version("agentdojo")
    except importlib.metadata.PackageNotFoundError:
        return None


def check_version(manifest: dict[str, Any]) -> str:
    """Refuse to measure a version other than the pinned one."""
    pinned = manifest["package"]["version"]
    installed = installed_version()
    if pinned is None:
        raise SystemExit(
            "manifest.json has no pinned agentdojo version. Install the version you "
            "intend to measure, put it in package.version, and rerun. Latest seen "
            f"upstream: {manifest['package'].get('latest_seen')}."
        )
    if installed is None:
        raise SystemExit(f"agentdojo is not installed. Run: pip install 'agentdojo=={pinned}'")
    if installed != pinned:
        raise SystemExit(
            f"agentdojo {installed} is installed but manifest.json pins {pinned}. "
            "Install the pinned version, or update the manifest deliberately."
        )
    return installed


def available_suites() -> list[str]:
    """The suites registered by the installed AgentDojo.

    TODO: read them from the pinned install rather than hard-coding a list, so
    the set always matches the version measured. The upstream CLI takes suites
    with `-s`; its registry lives in the `agentdojo` package.
    """
    raise NotImplementedError(
        "available_suites: enumerate suites from the installed agentdojo "
        "(see `python -m agentdojo.scripts.benchmark --help`)"
    )


def build_pipeline(firewall: Any, arm: harness.Arm, model: str) -> Any:
    """Build the agent pipeline for one arm, with ACF in it.

    The ACF side is fixed and does not need inventing:

    - detect: every tool result the agent is about to read goes through
      `harness.screen_observation(firewall, text)`, which returns the text to
      show the agent and the verdict. BLOCK replaces the text with an error.
    - gate: every tool call the model chooses goes through
      `harness.gate_tool_call(firewall, name, params)` before it runs. BLOCK
      means the call must not execute.

    TODO: attach those two calls to the upstream pipeline. Check the class names
    and the hook points against the pinned version before writing this.
    """
    raise NotImplementedError(
        "build_pipeline: wrap AgentDojo's pipeline so tool results pass through "
        "harness.screen_observation and tool calls through harness.gate_tool_call"
    )


def run_case(pipeline: Any, suite: str, user_task: str, injection_task: str | None,
             arm: harness.Arm, attack: str) -> dict[str, Any]:
    """Run one task and return a record with the RECORD_FIELDS keys.

    TODO: drive the upstream task runner and read back its own verdicts:
    utility from the suite's utility check, attack_succeeded from the injection
    task's security check. Scoring must happen after enforcement, so a tool call
    ACF blocked counts as an unsuccessful attack.
    """
    raise NotImplementedError("run_case: run one AgentDojo task through the pipeline")


# ── scoring ──────────────────────────────────────────────────────────────────


def compute_scores(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Benign utility, utility under attack and ASR, per arm and suite.

    Benign utility comes from the records with no injection task, the other two
    from the records with one. A record whose `error` is set is left out of the
    scores and counted separately, as upstream does.
    """
    scored = [r for r in records if not r.get("error")]
    by_arm: dict[str, Any] = {}
    for arm in sorted({r["arm"] for r in scored}):
        arm_records = [r for r in scored if r["arm"] == arm]
        suites = sorted({r["suite"] for r in arm_records})
        by_arm[arm] = {
            "overall": _score_group(arm_records),
            "suites": {suite: _score_group([r for r in arm_records if r["suite"] == suite])
                       for suite in suites},
            "errors": sum(1 for r in records if r["arm"] == arm and r.get("error")),
        }
    return by_arm


def _score_group(records: list[dict[str, Any]]) -> dict[str, Any]:
    benign = [r for r in records if r["injection_task"] is None]
    attacked = [r for r in records if r["injection_task"] is not None]
    return {
        "benign_cases": len(benign),
        "attacked_cases": len(attacked),
        "benign_utility": harness.rate(sum(1 for r in benign if r["utility"]), len(benign)),
        "utility_under_attack": harness.rate(
            sum(1 for r in attacked if r["utility"]), len(attacked)
        ),
        "asr": harness.rate(sum(1 for r in attacked if r["attack_succeeded"]), len(attacked)),
        "blocked_calls": sum(r.get("blocked_calls", 0) for r in records),
        "altered_observations": sum(r.get("altered_observations", 0) for r in records),
    }


def render_markdown(summary: dict[str, Any]) -> str:
    prov = summary["provenance"]
    lines = [
        "# AgentDojo with ACF in the agent loop",
        "",
        f"Agent model `{prov['model']}`, attack `{prov['attack']}`, "
        f"agentdojo `{prov['agentdojo_version']}`, semantic scanner `{prov['semantic_scanner']}`.",
        f"ACF commit `{prov['acf_commit']}`.",
        "",
        "Rates are measured after enforcement: a tool call ACF blocks counts as an "
        "unsuccessful attack. Utility is the benchmark's own task check.",
        "",
        "| Arm | Benign utility | Utility under attack | ASR | Blocked calls | Altered observations | Errors |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for arm, scores in summary["scores"].items():
        overall = scores["overall"]
        lines.append(
            f"| {arm} | {harness.percent(overall['benign_utility'])} | "
            f"{harness.percent(overall['utility_under_attack'])} | "
            f"{harness.percent(overall['asr'])} | {overall['blocked_calls']} | "
            f"{overall['altered_observations']} | {scores['errors']} |"
        )
    suites = sorted({suite for scores in summary["scores"].values() for suite in scores["suites"]})
    if suites:
        lines += ["", "## By suite", "",
                  "| Arm | Suite | Benign utility | Utility under attack | ASR |",
                  "|---|---|---:|---:|---:|"]
        for arm, scores in summary["scores"].items():
            for suite in suites:
                group = scores["suites"].get(suite)
                if group:
                    lines.append(
                        f"| {arm} | {suite} | {harness.percent(group['benign_utility'])} | "
                        f"{harness.percent(group['utility_under_attack'])} | "
                        f"{harness.percent(group['asr'])} |"
                    )
    lines += ["", "## Sidecars", ""]
    for entry in summary.get("sidecars", []):
        lines.append(f"- allowlist `{entry['allowlist']}`: preflight "
                     f"{', '.join(c['id'] + '=' + c['verdict'] for c in entry['preflight'] or [])}")
    return "\n".join(lines) + "\n"


# ── run ──────────────────────────────────────────────────────────────────────


def allowlist_for(arm: harness.Arm, suite_tools: tuple[str, ...],
                  task_tools: tuple[str, ...]) -> tuple[str, ...]:
    """Which tools the sidecar allows for this arm.

    A global allowlist permits every tool in the suite, which is the weaker
    claim: the benchmark supplies both the tasks and the allowed names. A task
    allowlist permits only what the task needs, which is least privilege and the
    stronger claim, but it assumes the task's tools are known in advance. Report
    both and say which is which.
    """
    if arm.gate == "global":
        return tuple(sorted(set(suite_tools)))
    if arm.gate == "task":
        return tuple(sorted(set(task_tools)))
    return ()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--suites", default="all", help="comma list, or all")
    parser.add_argument("--arms", default="none,detect,gate-global,full-global")
    parser.add_argument("--attack", default=DEFAULT_ATTACK, help="upstream attack name")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--limit", type=int, default=None, help="user tasks per suite")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--semantic", choices=("off", "tfidf", "sentence-transformer"),
                        default="off")
    parser.add_argument("--build-sidecar", action="store_true")
    parser.add_argument("--sidecar-binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR)
    parser.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS_DIR)
    parser.add_argument("--dry-run", action="store_true",
                        help="start the sidecars, run preflight, print the plan, make no model calls")
    args = parser.parse_args(argv)
    args.arms = harness.csv_choices(args.arms, list(harness.ARMS), "arms")
    if args.workers < 1:
        raise SystemExit("--workers must be at least 1")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    harness.clear_sdk_env()
    manifest = harness.load_manifest(MANIFEST_PATH)
    # A dry run exercises the ACF half only, so it does not need the upstream
    # package installed or the manifest pinned.
    version = "unpinned" if args.dry_run and manifest["package"]["version"] is None \
        else check_version(manifest)

    if args.build_sidecar or not args.sidecar_binary.exists():
        harness.build_sidecar(args.sidecar_binary)

    if args.suites == "all":
        suites = [] if args.dry_run else available_suites()
    else:
        suites = [s.strip() for s in args.suites.split(",") if s.strip()]
    print(f"agentdojo {version}: suites={suites} arms={args.arms} model={args.model} "
          f"attack={args.attack} semantic={args.semantic}", flush=True)

    out_dir = harness.new_output_dir(args.results_dir, f"{args.model}")
    work_dir = out_dir / "work"
    factory = harness.FirewallFactory(None if args.semantic == "off" else args.semantic)
    pool = harness.SidecarPool(args.sidecar_binary, work_dir, factory, name="agentdojo")

    records: list[dict[str, Any]] = []
    started = time.monotonic()
    try:
        if args.dry_run:
            # Exercise the ACF half only: one sidecar, preflight, no model calls.
            socket_path = pool.socket_for(("ACFDryRunTool",))
            print(f"dry run: sidecar ready on {socket_path}, preflight passed", flush=True)
        else:
            for arm_name in args.arms:
                arm = harness.ARMS[arm_name]
                for suite in suites:
                    # TODO: enumerate the suite's user tasks and injection tasks,
                    # build the pipeline for this arm, and run each case.
                    pipeline = build_pipeline(factory.get(pool.socket_for(())), arm, args.model)
                    records.append(run_case(pipeline, suite, "user_task_0", None, arm, args.attack))
        summary = {
            "provenance": harness.provenance(
                Path(__file__), MANIFEST_PATH, args.sidecar_binary,
                {
                    "agentdojo_version": version,
                    "model": args.model,
                    "attack": args.attack,
                    "arms": args.arms,
                    "suites": suites,
                    "limit_per_suite": args.limit,
                    "semantic_scanner": args.semantic,
                    "workers": args.workers,
                    "dry_run": args.dry_run,
                },
            ),
            "scores": compute_scores(records),
            "sidecars": pool.describe(),
            "cases": len(records),
            "elapsed_s": round(time.monotonic() - started, 1),
        }
    finally:
        pool.close()

    harness.write_records(out_dir / "records.jsonl", records)
    harness.write_summary(out_dir, summary, render_markdown(summary))
    print(f"results: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
