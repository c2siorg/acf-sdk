#!/usr/bin/env python3
"""Run Agent Security Bench (ASB) with ACF enforcement. SCAFFOLD.

ASB is the broad-coverage benchmark: it spans direct prompt injection,
observation prompt injection, memory poisoning, plan-of-thought backdoors and
mixed attacks over many agents and tools. Its value for the paper is showing
which ACF enforcement point stops which attack class, since ACF mediates
prompts, retrieved content, tool calls and memory separately. It backs
§eval-asb.

What this file already does:

- requires a pinned upstream commit and checks the clone matches it
- builds the sidecar and starts one per tool allowlist, with preflight checks
- maps each ASB attack class to the ACF hook that should intercept it
- scores records into ASR, refuse rate, benign success and where the attack was
  intercepted, per attack class and arm
- writes records, summary.json and summary.md with full provenance

What is left to implement, marked TODO below:

1. `load_cases`  — read the attack cases for a class from the pinned clone.
2. `run_case`    — run one case with ACF in the loop and return a record.

Choose the integration mode before writing those, and record it in the run:

- `hooks` replays each attack's text and tool calls through the ACF hooks with
  no agent. Cheap and deterministic, but it measures detection and
  authorisation, not agent attack success. This is what `benchmarks/` does for
  InjecAgent.
- `agent` drives ASB's own agent loop with ACF between the agent and its tools
  and memory, which is what the paper's ASR numbers need. It costs model calls
  and needs upstream's runner wired to the hooks.

Until those exist, `--dry-run` works and is worth running: it starts the
sidecars, runs the preflight controls and prints the plan.
"""

from __future__ import annotations

import argparse
import json
import subprocess
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
DEFAULT_UPSTREAM_DIR = HERE / "upstream" / "ASB"
DEFAULT_MODEL = "gpt-4o-2024-08-06"
MODES = ("hooks", "agent")

ATTACK_TYPES = (
    "direct_prompt_injection",
    "observation_prompt_injection",
    "memory_poisoning",
    "pot_backdoor",
    "mixed",
)

# Which ACF enforcement point is meant to stop each attack class. The run
# reports where each attack was actually intercepted, so a mismatch with this
# table is a finding rather than a bug in the harness.
EXPECTED_HOOK = {
    "direct_prompt_injection": "on_prompt",
    "observation_prompt_injection": "on_context",
    "memory_poisoning": "on_memory",
    "pot_backdoor": "on_prompt",
    "mixed": "multiple",
}

# One record per (attack type, agent, case, arm).
RECORD_FIELDS = (
    "attack_type", "agent", "case_id", "arm", "attack_succeeded", "refused",
    "benign_success", "intercepted_at", "verdicts", "error",
)


# ── upstream ─────────────────────────────────────────────────────────────────


def check_clone(manifest: dict[str, Any], upstream_dir: Path) -> str:
    """Require a pinned commit and a clone checked out at it."""
    commit = manifest.get("commit")
    if not commit:
        raise SystemExit(
            "manifest.json has no pinned ASB commit. Clone the repo, pick the commit "
            "you intend to measure, put its full SHA in manifest.json, and rerun:\n"
            f"  git clone https://github.com/{manifest['repository']} {upstream_dir}"
        )
    if not upstream_dir.exists():
        raise SystemExit(
            f"{upstream_dir} does not exist. Run:\n"
            f"  git clone https://github.com/{manifest['repository']} {upstream_dir}\n"
            f"  git -C {upstream_dir} checkout {commit}"
        )
    try:
        head = subprocess.check_output(
            ["git", "-C", str(upstream_dir), "rev-parse", "HEAD"], text=True
        ).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise SystemExit(f"could not read HEAD of {upstream_dir}: {exc}") from exc
    if head != commit:
        raise SystemExit(
            f"{upstream_dir} is at {head} but manifest.json pins {commit}. Run:\n"
            f"  git -C {upstream_dir} checkout {commit}"
        )
    return head


def load_cases(upstream_dir: Path, attack_type: str, limit: int | None) -> list[dict[str, Any]]:
    """Attack cases for one class, from the pinned clone.

    TODO: read them from upstream's config and data files (the manifest lists
    the config paths seen in its README) and hash every file read into the run's
    provenance, so a changed dataset cannot pass unnoticed.
    """
    raise NotImplementedError(
        f"load_cases: read {attack_type} cases from the pinned ASB clone at {upstream_dir}"
    )


def run_case(firewall: Any, mode: str, arm: harness.Arm, case: dict[str, Any],
             model: str) -> dict[str, Any]:
    """Run one ASB case and return a record with the RECORD_FIELDS keys.

    The ACF calls are fixed: user prompts go through `firewall.on_prompt`,
    observations through `harness.screen_observation`, tool calls through
    `harness.gate_tool_call`, and memory writes and reads through
    `firewall.on_memory`. Record which of those first returned BLOCK or
    SANITISE as `intercepted_at`, because per-hook attribution is the reason
    this benchmark is in the paper.

    TODO: in `hooks` mode, replay the case's text and calls through those hooks.
    In `agent` mode, drive upstream's agent loop with the hooks in place and read
    its own success, refusal and benign-run verdicts.
    """
    raise NotImplementedError(f"run_case: {mode} mode for ASB is not implemented yet")


# ── scoring ──────────────────────────────────────────────────────────────────


def compute_scores(records: list[dict[str, Any]]) -> dict[str, Any]:
    """ASR, refuse rate, benign success and interception point, per arm.

    ASR and refuse rate are measured after enforcement. `benign_success` is
    upstream's no-attack performance, the utility side, and is only counted on
    records that ran a benign task.
    """
    scored = [r for r in records if not r.get("error")]
    by_arm: dict[str, Any] = {}
    for arm in sorted({r["arm"] for r in scored}):
        arm_records = [r for r in scored if r["arm"] == arm]
        by_arm[arm] = {
            "overall": _score_group(arm_records),
            "attack_types": {
                attack_type: _score_group([r for r in arm_records if r["attack_type"] == attack_type])
                for attack_type in sorted({r["attack_type"] for r in arm_records})
            },
            "errors": sum(1 for r in records if r["arm"] == arm and r.get("error")),
        }
    return by_arm


def _score_group(records: list[dict[str, Any]]) -> dict[str, Any]:
    benign = [r for r in records if r.get("benign_success") is not None]
    intercepted: dict[str, int] = {}
    for record in records:
        where = record.get("intercepted_at") or "not_intercepted"
        intercepted[where] = intercepted.get(where, 0) + 1
    return {
        "cases": len(records),
        "asr": harness.rate(sum(1 for r in records if r["attack_succeeded"]), len(records)),
        "refuse_rate": harness.rate(sum(1 for r in records if r.get("refused")), len(records)),
        "benign_success": harness.rate(sum(1 for r in benign if r["benign_success"]), len(benign)),
        "intercepted_at": dict(sorted(intercepted.items())),
    }


def render_markdown(summary: dict[str, Any]) -> str:
    prov = summary["provenance"]
    lines = [
        "# Agent Security Bench with ACF enforcement",
        "",
        f"Mode `{prov['mode']}`, agent model `{prov['model']}`, "
        f"semantic scanner `{prov['semantic_scanner']}`.",
        f"ACF commit `{prov['acf_commit']}`, ASB commit `{prov['asb_commit']}`.",
        "",
        "Rates are measured after enforcement. `hooks` mode measures detection and "
        "authorisation, not agent attack success; only `agent` mode gives ASR.",
        "",
        "| Arm | Cases | ASR | Refuse rate | Benign success | Errors |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for arm, scores in summary["scores"].items():
        overall = scores["overall"]
        lines.append(
            f"| {arm} | {overall['cases']} | {harness.percent(overall['asr'])} | "
            f"{harness.percent(overall['refuse_rate'])} | "
            f"{harness.percent(overall['benign_success'])} | {scores['errors']} |"
        )
    attack_types = sorted(
        {a for scores in summary["scores"].values() for a in scores["attack_types"]}
    )
    if attack_types:
        lines += ["", "## By attack class", "",
                  "| Arm | Attack class | Expected hook | ASR | Intercepted at |",
                  "|---|---|---|---:|---|"]
        for arm, scores in summary["scores"].items():
            for attack_type in attack_types:
                group = scores["attack_types"].get(attack_type)
                if group:
                    where = ", ".join(f"{k}={v}" for k, v in group["intercepted_at"].items())
                    lines.append(
                        f"| {arm} | {attack_type} | {EXPECTED_HOOK.get(attack_type, '?')} | "
                        f"{harness.percent(group['asr'])} | {where} |"
                    )
    return "\n".join(lines) + "\n"


# ── run ──────────────────────────────────────────────────────────────────────


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--mode", choices=MODES, default="hooks")
    parser.add_argument("--attack-types", default=",".join(ATTACK_TYPES))
    parser.add_argument("--arms", default="none,detect,full-global")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--limit", type=int, default=None, help="cases per attack class")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--semantic", choices=("off", "tfidf", "sentence-transformer"),
                        default="off")
    parser.add_argument("--upstream-dir", type=Path, default=DEFAULT_UPSTREAM_DIR)
    parser.add_argument("--build-sidecar", action="store_true")
    parser.add_argument("--sidecar-binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS_DIR)
    parser.add_argument("--dry-run", action="store_true",
                        help="start the sidecars, run preflight, print the plan, make no model calls")
    args = parser.parse_args(argv)
    args.arms = harness.csv_choices(args.arms, list(harness.ARMS), "arms")
    args.attack_types = harness.csv_choices(args.attack_types, ATTACK_TYPES, "attack-types")
    if args.workers < 1:
        raise SystemExit("--workers must be at least 1")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    harness.clear_sdk_env()
    manifest = harness.load_manifest(MANIFEST_PATH)
    asb_commit = "unpinned" if args.dry_run and not manifest.get("commit") else \
        check_clone(manifest, args.upstream_dir)

    if args.build_sidecar or not args.sidecar_binary.exists():
        harness.build_sidecar(args.sidecar_binary)

    print(f"ASB {asb_commit[:12]}: mode={args.mode} attacks={args.attack_types} "
          f"arms={args.arms} model={args.model} semantic={args.semantic}", flush=True)

    out_dir = harness.new_output_dir(args.results_dir, f"{args.mode}-{args.model}")
    work_dir = out_dir / "work"
    factory = harness.FirewallFactory(None if args.semantic == "off" else args.semantic)
    pool = harness.SidecarPool(args.sidecar_binary, work_dir, factory, name="asb")

    records: list[dict[str, Any]] = []
    started = time.monotonic()
    try:
        if args.dry_run:
            socket_path = pool.socket_for(("ACFDryRunTool",))
            print(f"dry run: sidecar ready on {socket_path}, preflight passed", flush=True)
        else:
            for arm_name in args.arms:
                arm = harness.ARMS[arm_name]
                firewall = factory.get(pool.socket_for(()))
                for attack_type in args.attack_types:
                    for case in load_cases(args.upstream_dir, attack_type, args.limit):
                        records.append(run_case(firewall, args.mode, arm, case, args.model))
        summary = {
            "provenance": harness.provenance(
                Path(__file__), MANIFEST_PATH, args.sidecar_binary,
                {
                    "asb_commit": asb_commit,
                    "mode": args.mode,
                    "model": args.model,
                    "arms": args.arms,
                    "attack_types": args.attack_types,
                    "limit_per_attack_type": args.limit,
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
