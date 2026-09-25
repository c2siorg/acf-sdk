#!/usr/bin/env python3
"""Run one AgentDojo condition/suite/attack combination and record the result.

Scaffold only -- runnable end to end for condition C0 (no ACF hook). Every
other condition raises NotImplementedError from acf_pipeline.build_pipeline()
until its ACF wiring lands; this CLI catches that and reports it as a clear
"not wired yet" result rather than a crash.

Requires `pip install agentdojo` (see README.md). --model can be a real
ModelsEnum value against a cloud provider (needs that provider's API key,
e.g. OPENAI_API_KEY), or 'local'/'vllm_parsed' against an OpenAI-compatible
server on localhost (paired with --model-id, no API key needed) -- see
README.md's "Live-tested against a local model" for a real, working example
against Ollama.
"""
from __future__ import annotations

import argparse
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
SDK_ROOT = REPO_ROOT / "sdk" / "python"
if str(SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(SDK_ROOT))
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from conditions import CONDITIONS  # noqa: E402
from acf_pipeline import build_pipeline  # noqa: E402

RESULTS_DIR = Path(__file__).resolve().parent / "results"


def _import_agentdojo():
    try:
        import agentdojo  # noqa: F401
    except ImportError as exc:  # pragma: no cover - environment-dependent
        raise SystemExit(
            "agentdojo is not installed. pip install agentdojo (see "
            "benchmarks/agentdojo/README.md)."
        ) from exc


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--condition", required=True, choices=sorted(CONDITIONS.keys()))
    parser.add_argument(
        "--suite", required=True, choices=["banking", "slack", "travel", "workspace"]
    )
    parser.add_argument("--attack", required=True, help="AgentDojo attack name, e.g. important_instructions")
    parser.add_argument(
        "--model",
        required=True,
        help="AgentDojo ModelsEnum value, e.g. gpt-4o-mini-2024-07-18 (needs the matching "
        "provider's API key), or 'local'/'vllm_parsed' to talk to an OpenAI-compatible "
        "server on localhost (e.g. Ollama) -- pair with --model-id and, for 'local', the "
        "LOCAL_LLM_PORT env var if not on port 8000. No API key needed for either.",
    )
    parser.add_argument(
        "--model-id",
        default=None,
        help="Model name the local server serves, e.g. llama3.2:latest. Only used when "
        "--model is 'local' or 'vllm_parsed'.",
    )
    parser.add_argument("--benchmark-version", default="v1.2.2")
    parser.add_argument("--user-tasks", nargs="*", default=None, help="Subset of user task IDs; default all")
    parser.add_argument("--out", type=Path, default=None, help="Output JSON path; default auto-named under results/")
    return parser.parse_args(argv)


def run(args: argparse.Namespace) -> dict[str, Any]:
    _import_agentdojo()
    from agentdojo.attacks.attack_registry import load_attack
    from agentdojo.benchmark import aggregate_results, benchmark_suite_with_injections
    from agentdojo.task_suite.load_suites import get_suite

    condition = CONDITIONS[args.condition]
    suite = get_suite(args.benchmark_version, args.suite)

    record: dict[str, Any] = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scaffold": "benchmarks/agentdojo (WIP -- see README.md)",
        "condition": {
            "name": condition.name,
            "description": condition.description,
            "acf_hooks": list(condition.acf_hooks),
        },
        "suite": args.suite,
        "attack": args.attack,
        "model": args.model,
        "benchmark_version": args.benchmark_version,
        "environment": {"python": platform.python_version(), "platform": platform.platform()},
    }

    try:
        pipeline = build_pipeline(condition, args.model, model_id=args.model_id)
    except NotImplementedError as exc:
        record["status"] = "not_wired"
        record["detail"] = str(exc)
        return record

    attack = load_attack(args.attack, suite, pipeline)
    # benchmark_suite_with_injections doesn't open a logger context itself --
    # it calls run_task_with(out)_injection_tasks directly, which reads
    # Logger.get() to build a TraceLogger. With no context entered,
    # Logger.get() falls back to a bare, never-__enter__-ed NullLogger()
    # whose .logdir was never set, and that AttributeErrors. Confirmed live
    # against a local Ollama model (see README.md) -- NullLogger's own
    # __enter__ doesn't push onto LOGGER_STACK either, so `with NullLogger():`
    # doesn't fix it; OutputLogger does, via the base Logger.__enter__/__exit__
    # it inherits.
    from agentdojo.logging import OutputLogger

    with OutputLogger(logdir=None):
        results = benchmark_suite_with_injections(
            agent_pipeline=pipeline,
            suite=suite,
            attack=attack,
            logdir=None,
            force_rerun=False,
            user_tasks=args.user_tasks,
            benchmark_version=args.benchmark_version,
        )

    record["status"] = "completed"
    record["utility_results"] = {
        f"{u}|{i}": v for (u, i), v in results["utility_results"].items()
    }
    record["security_results"] = {
        f"{u}|{i}": v for (u, i), v in results["security_results"].items()
    }
    record["injection_tasks_utility_results"] = dict(results["injection_tasks_utility_results"])
    record["utility_rate"] = aggregate_results([results["utility_results"]])
    record["security_rate"] = aggregate_results([results["security_results"]])
    record["attack_success_rate"] = 1.0 - record["security_rate"]
    return record


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    record = run(args)

    out = args.out
    if out is None:
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        out = RESULTS_DIR / f"{args.condition}_{args.suite}_{args.attack}.json"
    out.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if record["status"] == "not_wired":
        print(f"{args.condition} not wired yet: {record['detail']}", file=sys.stderr)
        raise SystemExit(1)
    print(f"Wrote {out}")


if __name__ == "__main__":
    main()
