#!/usr/bin/env python3
"""Run AgentDojo 0.1.35 task suites with ACF enforcement in the agent loop.

The runner enumerates the pinned suite registry, executes benign and attacked
cases through AgentDojo evaluators, and records per-case outcomes and ACF
verdicts. Model and enforcement errors are recorded separately from scores.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))  # benchmarkv2/ on the path, for `common`

from common import harness  # noqa: E402

MANIFEST_PATH = HERE / "manifest.json"
DEFAULT_BINARY = HERE / ".bin" / f"sidecar{harness.EXE}"
DEFAULT_RESULTS_DIR = HERE / "results"
DEFAULT_MODEL = "gpt-4o-2024-08-06"
UNLISTED_OPENAI_MODELS = {DEFAULT_MODEL, "gpt-4o-2024-11-20"}
DEFAULT_ATTACK = "tool_knowledge"
DEFAULT_BENCHMARK_VERSION = "v1.2.2"

# One record per (suite, user task, injection task, arm). `injection_task` is
# None for the benign run of a user task.
RECORD_FIELDS = (
    "suite", "user_task", "injection_task", "requested_injection_task",
    "effective_injection_task", "arm", "utility", "attack_succeeded",
    "attack_success_source", "allowlist_tools", "task_tools", "task_allowlist_source",
    "tool_call_verdicts", "observation_verdicts", "blocked_calls",
    "sanitised_tool_calls_not_executed", "blocked_observations",
    "altered_observations", "legitimate_call_verdicts", "error",
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
    """Return suites registered for the pinned AgentDojo benchmark version."""
    manifest = harness.load_manifest(MANIFEST_PATH)
    benchmark_version = manifest.get("benchmark_version", DEFAULT_BENCHMARK_VERSION)
    try:
        return list(suite_registry(benchmark_version))
    except KeyError:
        raise RuntimeError(
            f"benchmark version {benchmark_version!r} is not registered by AgentDojo"
        ) from None


def suite_registry(benchmark_version: str) -> dict[str, Any]:
    from agentdojo.task_suite.load_suites import get_suites

    return get_suites(benchmark_version)


def model_provider_for(model: str) -> str:
    """Resolve an AgentDojo model, including the exact pinned GPT-4o checkpoint."""
    from agentdojo.models import MODEL_PROVIDERS, ModelsEnum

    if model in UNLISTED_OPENAI_MODELS:
        return "openai"
    try:
        return MODEL_PROVIDERS[ModelsEnum(model)]
    except ValueError:
        raise ValueError(
            f"model {model!r} is not supported by AgentDojo 0.1.35; choose a registered model"
        ) from None


def register_attack_model_name(model: str) -> None:
    """Register the attack prompt family without changing the requested model ID."""
    from agentdojo.attacks.base_attacks import MODEL_NAMES

    if model in UNLISTED_OPENAI_MODELS:
        MODEL_NAMES[model] = MODEL_NAMES["gpt-4o-2024-05-13"]


@dataclass
class ApiAttemptBudget:
    limit: int
    used: int = 0
    max_output_tokens: int | None = None
    prompt_tokens: int = 0
    completion_tokens: int = 0
    response_models: set[str] = field(default_factory=set)

    def take(self) -> None:
        if self.used >= self.limit:
            raise harness.BudgetExceeded(f"API attempt cap of {self.limit} reached")
        self.used += 1


def cap_openai_client(client: Any, budget: ApiAttemptBudget) -> Any:
    """Count each OpenAI request attempt, including AgentDojo retries."""
    client = client.with_options(max_retries=0, timeout=45.0)
    completions = client.chat.completions
    create = completions.create

    def capped_create(*args: Any, **kwargs: Any) -> Any:
        budget.take()
        if budget.max_output_tokens is not None:
            kwargs["max_tokens"] = budget.max_output_tokens
        response = create(*args, **kwargs)
        usage = getattr(response, "usage", None)
        if usage is not None:
            budget.prompt_tokens += usage.prompt_tokens or 0
            budget.completion_tokens += usage.completion_tokens or 0
        response_model = getattr(response, "model", None)
        if response_model:
            budget.response_models.add(response_model)
        return response

    completions.create = capped_create
    return client


def build_model(model: str, model_id: str | None = None,
                budget: ApiAttemptBudget | None = None,
                azure_deployment: str | None = None) -> Any:
    """Build AgentDojo's LLM while preserving the requested model identifier."""
    from agentdojo.agent_pipeline.agent_pipeline import get_llm

    provider = model_provider_for(model)
    register_attack_model_name(model)
    if azure_deployment:
        if provider != "openai":
            raise ValueError("Azure deployment requires an OpenAI model")
        from openai import AzureOpenAI
        from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM

        client = AzureOpenAI(api_version="2024-10-21")
        llm = OpenAILLM(client, azure_deployment)
    else:
        llm = get_llm(provider, model, model_id, tool_delimiter="tool")
    if budget is not None:
        if provider != "openai":
            raise ValueError("API attempt cap currently supports OpenAI models only")
        llm.client = cap_openai_client(llm.client, budget)
    return llm


def load_attack(attack_name: str, suite: Any, pipeline: Any) -> Any:
    from agentdojo.attacks.attack_registry import load_attack as upstream_load_attack

    return upstream_load_attack(attack_name, suite, pipeline)


def task_tool_names(suite: Any, user_task_id: str) -> tuple[str, ...]:
    """Derive task scope from the task definition's canonical ground-truth calls."""
    try:
        task = suite.get_user_task_by_id(user_task_id)
        environment = suite.load_and_inject_default_environment({})
        task_environment = task.init_environment(environment)
        calls = task.ground_truth(task_environment)
        names = tuple(sorted({call.function for call in calls}))
        suite_names = {tool.name for tool in suite.tools}
    except Exception as exc:
        raise ValueError(
            f"cannot derive task-scoped tools for {user_task_id} from ground truth "
            f"({type(exc).__name__})"
        ) from None
    if not names or not set(names).issubset(suite_names):
        raise ValueError(f"cannot derive task-scoped tools for {user_task_id} from ground truth")
    return names


def select_task_ids(task_ids: Any, limit: int | None = None) -> list[str]:
    """Select a stable numeric task prefix for reproducible limited runs."""
    if limit is not None and limit < 1:
        raise ValueError("limit must be positive")

    def task_key(task_id: str) -> tuple[str, int, str]:
        match = re.fullmatch(r"(.*?)(\d+)", task_id)
        return (match.group(1), int(match.group(2)), task_id) if match else (task_id, -1, task_id)

    selected = sorted(task_ids, key=task_key)
    return selected if limit is None else selected[:limit]


def select_injection_task_ids(task_ids: Any, limit: int | None = None,
                              is_dos: bool = False) -> list[str]:
    """Select injection tasks, retaining AgentDojo's effective DoS task."""
    if limit is not None and limit < 1:
        raise ValueError("injection limit must be positive")
    selected = list(task_ids)[:1] if is_dos else select_task_ids(task_ids)
    return selected if limit is None else selected[:limit]


@dataclass
class CaseTrace:
    tool_call_verdicts: list[dict[str, Any]] = field(default_factory=list)
    observation_verdicts: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def sanitised_tool_calls_not_executed(self) -> int:
        return sum(event["verdict"] == "SANITISE" for event in self.tool_call_verdicts)

    def reset(self) -> None:
        self.tool_call_verdicts.clear()
        self.observation_verdicts.clear()
        self.errors.clear()


def tools_executor_class() -> type:
    """Build the AgentDojo executor that gates calls and screens results in-place."""
    from agentdojo.agent_pipeline.errors import AbortAgentError
    from agentdojo.agent_pipeline.tool_execution import ToolsExecutor
    from agentdojo.types import text_content_block_from_string

    class ACFToolsExecutor(ToolsExecutor):
        def __init__(self, firewall: Any, arm: harness.Arm, trace: CaseTrace) -> None:
            super().__init__()
            self.firewall = firewall
            self.arm = arm
            self.trace = trace

        def query(self, query: str, runtime: Any, env: Any = None, messages: Any = (),
                  extra_args: Any = None) -> Any:
            calls = (messages[-1].get("tool_calls") or []) if messages else []
            if self.arm.gate is not None and calls:
                events = []
                denied = False
                for call in calls:
                    name = call.function
                    try:
                        verdict = harness.gate_tool_call(self.firewall, name, dict(call.args))
                    except Exception as exc:
                        verdict = "ERROR"
                        self.trace.errors.append(f"tool_call_error:{type(exc).__name__}")
                    events.append({
                        "tool": name,
                        "verdict": verdict,
                        "execution_attempted": False,
                    })
                    denied = denied or verdict != "ALLOW"
                self.trace.tool_call_verdicts.extend(events)
                if denied:
                    safe_messages = [*messages[:-1], {**messages[-1], "tool_calls": []}]
                    raise AbortAgentError("ACF withheld the tool call", safe_messages, env)
                for event in events:
                    event["execution_attempted"] = True

            result = super().query(query, runtime, env, messages, extra_args or {})
            if not self.arm.detect:
                return result

            next_query, next_runtime, next_env, next_messages, next_args = result
            checked_messages = list(next_messages)
            for index in range(len(messages), len(checked_messages)):
                message = checked_messages[index]
                if message.get("role") != "tool":
                    continue
                content = message.get("content") or []
                text_parts = []
                unsupported_content = False
                for block in content:
                    if not isinstance(block, dict) or block.get("type") != "text":
                        unsupported_content = True
                        break
                    text_parts.append(str(block.get("content", "")))
                tool_error = message.get("error")
                if tool_error is not None:
                    text_parts.append(str(tool_error))
                original = "\n".join(text_parts)
                if unsupported_content:
                    visible = harness.WITHHELD_OBSERVATION
                    verdict = "UNSUPPORTED_BLOCKED"
                    self.trace.errors.append("unsupported_context_content")
                else:
                    try:
                        visible, verdict = harness.screen_observation(self.firewall, original)
                    except Exception as exc:
                        visible = harness.WITHHELD_OBSERVATION
                        verdict = "ERROR"
                        self.trace.errors.append(f"context_error:{type(exc).__name__}")
                self.trace.observation_verdicts.append({
                    "tool_call_id": message.get("tool_call_id"),
                    "verdict": verdict,
                    "had_tool_error": tool_error is not None,
                })
                if verdict != "ALLOW":
                    checked_messages[index] = {
                        **message,
                        "content": [text_content_block_from_string(visible)],
                        "error": None,
                    }
            return next_query, next_runtime, next_env, checked_messages, next_args

    return ACFToolsExecutor


def build_pipeline(firewall: Any, arm: harness.Arm, model: Any,
                   model_id: str | None = None,
                   budget: ApiAttemptBudget | None = None,
                   azure_deployment: str | None = None) -> Any:
    """Build AgentDojo's pipeline with enforcement inside its tool loop."""
    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, load_system_message
    from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
    from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, ToolsExecutor

    if (arm.detect or arm.gate is not None) and firewall is None:
        raise ValueError(f"arm {arm.name} requires a firewall")
    if isinstance(model, str):
        llm = build_model(model, model_id, budget, azure_deployment)
        llm_name = model
    else:
        if budget is not None:
            raise ValueError("budgeted pipelines require a model ID")
        llm = model
        llm_name = getattr(model, "name", type(model).__name__)

    trace = CaseTrace()
    if arm.detect or arm.gate is not None:
        executor = tools_executor_class()(firewall, arm, trace)
    else:
        executor = ToolsExecutor()
    tools_loop = ToolsExecutionLoop([executor, llm])
    pipeline = AgentPipeline([
        SystemMessage(load_system_message(None)),
        InitQuery(),
        llm,
        tools_loop,
    ])
    pipeline.name = f"{llm_name}-acf-{arm.name}"
    pipeline._acf_trace = trace
    return pipeline


def run_case(pipeline: Any, suite: Any, user_task: str, injection_task: str | None,
             arm: harness.Arm, attack: str, task_tools: tuple[str, ...] = (),
             allowlist: tuple[str, ...] = ()) -> dict[str, Any]:
    """Run a case through AgentDojo's utility and injection evaluators."""
    from agentdojo.logging import OutputLogger

    if isinstance(suite, str):
        version = harness.load_manifest(MANIFEST_PATH).get(
            "benchmark_version", DEFAULT_BENCHMARK_VERSION
        )
        suite = suite_registry(version)[suite]
    trace = getattr(pipeline, "_acf_trace", CaseTrace())
    trace.reset()
    requested_injection = injection_task
    effective_injection = injection_task
    utility = None
    attack_succeeded = None
    attack_success_source = None
    error = None
    try:
        user_task_object = suite.get_user_task_by_id(user_task)
        with OutputLogger(logdir=None):
            if injection_task is None:
                utility, _ = suite.run_task_with_pipeline(
                    pipeline, user_task_object, injection_task=None, injections={}
                )
            else:
                attack_object = load_attack(attack, suite, pipeline)
                if attack_object.is_dos_attack:
                    effective_injection = next(iter(suite.injection_tasks))
                injection_task_object = suite.get_injection_task_by_id(effective_injection)
                injections = attack_object.attack(user_task_object, injection_task_object)
                utility, security = suite.run_task_with_pipeline(
                    pipeline, user_task_object, injection_task_object, injections
                )
                if attack_object.is_dos_attack:
                    attack_succeeded = not utility
                    attack_success_source = "AgentDojo DoS convention: not utility"
                else:
                    attack_succeeded = bool(security)
                    attack_success_source = "AgentDojo injection-task security evaluator"
    except harness.BudgetExceeded:
        raise
    except Exception as exc:
        error = type(exc).__name__

    if trace.errors:
        error = ";".join(([error] if error else []) + list(dict.fromkeys(trace.errors)))
        utility = None
        attack_succeeded = None

    tool_events = [dict(event) for event in trace.tool_call_verdicts]
    observation_events = [dict(event) for event in trace.observation_verdicts]
    task_tool_set = set(task_tools)
    return {
        "suite": suite.name,
        "user_task": user_task,
        "injection_task": effective_injection,
        "requested_injection_task": requested_injection,
        "effective_injection_task": effective_injection,
        "arm": arm.name,
        "utility": None if utility is None else bool(utility),
        "attack_succeeded": attack_succeeded,
        "attack_success_source": attack_success_source,
        "allowlist_tools": list(allowlist),
        "task_tools": list(task_tools),
        "task_allowlist_source": "ground_truth" if arm.gate == "task" else None,
        "tool_call_verdicts": tool_events,
        "observation_verdicts": observation_events,
        "blocked_calls": sum(event["verdict"] == "BLOCK" for event in tool_events),
        "sanitised_tool_calls_not_executed": sum(
            event["verdict"] == "SANITISE" for event in tool_events
        ),
        "blocked_observations": sum(
            event["verdict"] in {"BLOCK", "ERROR", "UNSUPPORTED_BLOCKED"}
            for event in observation_events
        ),
        "altered_observations": sum(
            event["verdict"] != "ALLOW" for event in observation_events
        ),
        "legitimate_call_verdicts": [
            event["verdict"] for event in tool_events if event["tool"] in task_tool_set
        ],
        "error": error,
    }


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
        "sanitised_tool_calls_not_executed": sum(
            r.get("sanitised_tool_calls_not_executed", 0) for r in records
        ),
        "blocked_observations": sum(r.get("blocked_observations", 0) for r in records),
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
        "Rates use AgentDojo's own task and attack checks after enforcement.",
        "",
        "SANITISE tool calls are withheld because the shared gate helper does not return sanitized arguments.",
        "",
        "| Arm | Benign utility | Utility under attack | ASR | Blocked calls | SANITISE calls withheld | Blocked observations | Altered observations | Errors |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for arm, scores in summary["scores"].items():
        overall = scores["overall"]
        lines.append(
            f"| {arm} | {harness.percent(overall['benign_utility'])} | "
            f"{harness.percent(overall['utility_under_attack'])} | "
            f"{harness.percent(overall['asr'])} | {overall['blocked_calls']} | "
            f"{overall['sanitised_tool_calls_not_executed']} | "
            f"{overall['blocked_observations']} | {overall['altered_observations']} | "
            f"{scores['errors']} |"
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
    parser.add_argument("--model-id", default=None, help="model ID for AgentDojo local models")
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--azure-deployment", default=None,
                        help="Azure deployment name; --model records the deployed checkpoint")
    parser.add_argument("--limit", type=int, default=None, help="user tasks per suite")
    parser.add_argument("--injection-limit", type=int, default=None,
                        help="injection tasks per suite; DoS attacks use the upstream effective task")
    parser.add_argument("--max-api-calls", type=int, default=20,
                        help="hard cap on OpenAI request attempts across this run")
    parser.add_argument("--max-output-tokens", type=int, default=None,
                        help="optional output token cap per model request")
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--semantic", choices=("off", "tfidf", "sentence-transformer"),
                        default="off")
    parser.add_argument("--build-sidecar", action="store_true")
    parser.add_argument("--sidecar-binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS_DIR)
    parser.add_argument("--dry-run", action="store_true",
                        help="start the sidecars, run preflight, print the plan, make no model calls")
    args = parser.parse_args(argv)
    args.arms = harness.csv_choices(args.arms, list(harness.ARMS), "arms")
    if args.workers != 1:
        raise SystemExit("this runner executes cases sequentially; --workers must be 1")
    if args.limit is not None and args.limit < 1:
        raise SystemExit("--limit must be positive")
    if args.injection_limit is not None and args.injection_limit < 1:
        raise SystemExit("--injection-limit must be positive")
    if args.max_api_calls < 1:
        raise SystemExit("--max-api-calls must be positive")
    if args.max_output_tokens is not None and args.max_output_tokens < 1:
        raise SystemExit("--max-output-tokens must be positive")
    if args.azure_deployment and args.base_url:
        raise SystemExit("--azure-deployment and --base-url cannot be combined")
    return args


def attack_is_dos(attack_name: str) -> bool:
    from agentdojo.attacks.attack_registry import ATTACKS

    try:
        return bool(ATTACKS[attack_name].is_dos_attack)
    except KeyError:
        raise SystemExit(f"unknown AgentDojo attack: {attack_name}") from None


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if (not args.dry_run and not args.azure_deployment and not args.base_url
            and os.environ.get("OPENAI_BASE_URL")):
        raise SystemExit(
            "OPENAI_BASE_URL is set; pass --base-url explicitly or unset it "
            "so the provider configuration is recorded"
        )
    harness.clear_sdk_env()
    manifest = harness.load_manifest(MANIFEST_PATH)
    version = "not checked (dry run)" if args.dry_run else check_version(manifest)
    benchmark_version = manifest.get("benchmark_version", DEFAULT_BENCHMARK_VERSION)

    if not args.dry_run:
        provider = model_provider_for(args.model)
        if provider != "openai":
            raise SystemExit("live runs currently support OpenAI models only")
        if args.base_url and model_provider_for(args.model) != "openai":
            raise SystemExit("--base-url is supported only for AgentDojo OpenAI models")
        is_dos = attack_is_dos(args.attack)
        registered_suites = suite_registry(benchmark_version)
        suites_available = list(registered_suites)
        pinned_suites = manifest.get("suites")
        if pinned_suites is not None and set(pinned_suites) != set(suites_available):
            raise SystemExit("manifest.json suite list does not match the installed AgentDojo registry")
        if args.suites == "all":
            suites = suites_available
        else:
            suites = harness.csv_choices(args.suites, suites_available, "suites")
    elif args.suites == "all":
        suites = []
        registered_suites = {}
        is_dos = False
    else:
        suites = [part.strip() for part in args.suites.split(",") if part.strip()]
        registered_suites = {}
        is_dos = False

    needs_sidecar = args.dry_run or any(
        harness.ARMS[name].detect or harness.ARMS[name].gate is not None for name in args.arms
    )
    if args.build_sidecar or (needs_sidecar and not args.sidecar_binary.exists()):
        harness.build_sidecar(args.sidecar_binary)
    print(f"agentdojo {version}: suites={suites} arms={args.arms} model={args.model} "
          f"attack={args.attack} semantic={args.semantic}", flush=True)

    out_dir = harness.new_output_dir(args.results_dir, f"{args.model}")
    work_dir = out_dir / "work"
    factory = harness.FirewallFactory(None if args.semantic == "off" else args.semantic)
    pool = harness.SidecarPool(args.sidecar_binary, work_dir, factory, name="agentdojo")

    records: list[dict[str, Any]] = []
    budget = ApiAttemptBudget(args.max_api_calls, max_output_tokens=args.max_output_tokens)
    started = time.monotonic()
    previous_base_url = os.environ.get("OPENAI_BASE_URL")
    if args.base_url:
        os.environ["OPENAI_BASE_URL"] = args.base_url
    try:
        if args.dry_run:
            # Exercise the ACF half only: 1 sidecar, preflight, no model calls.
            socket_path = pool.socket_for(("ACFDryRunTool",))
            print(f"dry run: sidecar ready on {socket_path}, preflight passed", flush=True)
        else:
            for arm_name in args.arms:
                arm = harness.ARMS[arm_name]
                for suite_name in suites:
                    suite = registered_suites[suite_name]
                    suite_tools = tuple(sorted(tool.name for tool in suite.tools))
                    user_tasks = select_task_ids(suite.user_tasks, args.limit)
                    injection_tasks = select_injection_task_ids(
                        suite.injection_tasks, args.injection_limit, is_dos
                    )
                    for user_task in user_tasks:
                        task_tools = ()
                        if arm.gate == "task":
                            try:
                                task_tools = task_tool_names(suite, user_task)
                            except ValueError as exc:
                                raise SystemExit(str(exc)) from None
                        allowlist = allowlist_for(arm, suite_tools, task_tools)
                        firewall = None
                        if arm.detect or arm.gate is not None:
                            socket_path = pool.socket_for(allowlist)
                            firewall = factory.get(socket_path)
                        try:
                            pipeline = build_pipeline(
                                firewall, arm, args.model, model_id=args.model_id,
                                budget=budget,
                                azure_deployment=args.azure_deployment,
                            )
                        except Exception as exc:
                            raise SystemExit(
                                f"could not initialize AgentDojo model ({type(exc).__name__}); "
                                "check the selected model and provider configuration"
                            ) from None
                        records.append(run_case(
                            pipeline, suite, user_task, None, arm, args.attack,
                            task_tools=task_tools, allowlist=allowlist,
                        ))
                        for injection_task in injection_tasks:
                            records.append(run_case(
                                pipeline, suite, user_task, injection_task, arm, args.attack,
                                task_tools=task_tools, allowlist=allowlist,
                            ))
        summary = {
            "provenance": harness.provenance(
                Path(__file__), MANIFEST_PATH, args.sidecar_binary,
                {
                    "agentdojo_version": version,
                    "model": args.model,
                    "model_id": args.model_id,
                    "provider": "azure-openai" if args.azure_deployment else "openai",
                    "azure_deployment": args.azure_deployment,
                    "azure_api_version": "2024-10-21" if args.azure_deployment else None,
                    "openai_base_url_configured": bool(args.base_url),
                    "attack": args.attack,
                    "arms": args.arms,
                    "suites": suites,
                    "benchmark_version": benchmark_version,
                    "limit_per_suite": args.limit,
                    "injection_limit_per_suite": args.injection_limit,
                    "max_api_calls": budget.limit,
                    "api_calls_used": budget.used,
                    "max_output_tokens": budget.max_output_tokens,
                    "prompt_tokens": budget.prompt_tokens,
                    "completion_tokens": budget.completion_tokens,
                    "response_models": sorted(budget.response_models),
                    "temperature": "provider default; AgentDojo 0.1.35 omits its 0.0 value",
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
    except harness.BudgetExceeded as exc:
        partial = out_dir / "partial_records.jsonl"
        harness.write_records(partial, records)
        (out_dir / "partial_usage.json").write_text(json.dumps({
            "model": args.model,
            "azure_deployment": args.azure_deployment,
            "api_calls_used": budget.used,
            "max_api_calls": budget.limit,
            "max_output_tokens": budget.max_output_tokens,
            "prompt_tokens": budget.prompt_tokens,
            "completion_tokens": budget.completion_tokens,
            "response_models": sorted(budget.response_models),
        }, indent=2) + "\n", encoding="utf-8")
        raise SystemExit(
            f"{exc}; saved {len(records)} completed cases to {partial}; no scores written"
        ) from None
    finally:
        pool.close()
        if args.base_url:
            if previous_base_url is None:
                os.environ.pop("OPENAI_BASE_URL", None)
            else:
                os.environ["OPENAI_BASE_URL"] = previous_base_url

    harness.write_records(out_dir / "records.jsonl", records)
    harness.write_summary(out_dir, summary, render_markdown(summary))
    print(f"results: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
