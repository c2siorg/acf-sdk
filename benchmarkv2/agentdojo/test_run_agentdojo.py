from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).with_name("run_agentdojo.py")
SPEC = importlib.util.spec_from_file_location("run_agentdojo", MODULE_PATH)
assert SPEC and SPEC.loader
run_agentdojo = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = run_agentdojo
SPEC.loader.exec_module(run_agentdojo)

from common import harness  # noqa: E402


def record(arm: str, suite: str, injection: str | None, utility: bool,
           attack: bool | None = None, **extra) -> dict:
    return {
        "suite": suite, "user_task": "user_task_0", "injection_task": injection, "arm": arm,
        "utility": utility, "attack_succeeded": attack, "blocked_calls": 0,
        "altered_observations": 0, "legitimate_call_verdicts": [], "error": None, **extra,
    }


def test_compute_scores_splits_benign_from_attacked():
    records = [
        record("none", "workspace", None, True),
        record("none", "workspace", None, False),
        record("none", "workspace", "injection_task_0", True, attack=True),
        record("none", "workspace", "injection_task_1", False, attack=False),
    ]
    scores = run_agentdojo.compute_scores(records)["none"]["overall"]
    assert scores["benign_cases"] == 2 and scores["attacked_cases"] == 2
    assert scores["benign_utility"] == 0.5
    assert scores["utility_under_attack"] == 0.5
    assert scores["asr"] == 0.5


def test_compute_scores_reports_each_suite_and_arm():
    records = [
        record("none", "workspace", "i0", False, attack=True),
        record("none", "banking", "i0", False, attack=False),
        record("full-global", "workspace", "i0", True, attack=False, blocked_calls=1),
    ]
    scores = run_agentdojo.compute_scores(records)
    assert scores["none"]["suites"]["workspace"]["asr"] == 1.0
    assert scores["none"]["suites"]["banking"]["asr"] == 0.0
    assert scores["full-global"]["overall"]["asr"] == 0.0
    assert scores["full-global"]["overall"]["blocked_calls"] == 1


def test_compute_scores_excludes_errored_cases_but_counts_them():
    records = [
        record("none", "workspace", "i0", False, attack=True),
        record("none", "workspace", "i1", False, attack=None, error="api timeout"),
    ]
    scores = run_agentdojo.compute_scores(records)["none"]
    assert scores["overall"]["attacked_cases"] == 1
    assert scores["errors"] == 1


def test_compute_scores_on_no_records_is_empty_not_an_error():
    assert run_agentdojo.compute_scores([]) == {}


def test_allowlist_scope_controls_which_tools_are_permitted():
    arm_global, arm_task, arm_none = (harness.ARMS[n] for n in ("gate-global", "gate-task", "detect"))
    suite_tools, task_tools = ("b_tool", "a_tool", "b_tool"), ("a_tool",)
    assert run_agentdojo.allowlist_for(arm_global, suite_tools, task_tools) == ("a_tool", "b_tool")
    assert run_agentdojo.allowlist_for(arm_task, suite_tools, task_tools) == ("a_tool",)
    assert run_agentdojo.allowlist_for(arm_none, suite_tools, task_tools) == ()


def test_check_version_requires_a_pinned_and_matching_install(monkeypatch):
    monkeypatch.setattr(run_agentdojo, "installed_version", lambda: "0.1.35")
    with pytest.raises(SystemExit, match="no pinned agentdojo version"):
        run_agentdojo.check_version({"package": {"version": None, "latest_seen": "0.1.35"}})
    with pytest.raises(SystemExit, match="manifest.json pins 0.1.30"):
        run_agentdojo.check_version({"package": {"version": "0.1.30"}})
    assert run_agentdojo.check_version({"package": {"version": "0.1.35"}}) == "0.1.35"

    monkeypatch.setattr(run_agentdojo, "installed_version", lambda: None)
    with pytest.raises(SystemExit, match="not installed"):
        run_agentdojo.check_version({"package": {"version": "0.1.35"}})


def test_render_markdown_reports_every_arm():
    summary = {
        "provenance": {"model": "gpt-4o", "attack": "tool_knowledge", "agentdojo_version": "0.1.35",
                       "semantic_scanner": "off", "acf_commit": "abc"},
        "scores": run_agentdojo.compute_scores([
            record("none", "workspace", "i0", True, attack=True),
            record("full-global", "workspace", "i0", True, attack=False),
        ]),
        "sidecars": [{"allowlist": ["a_tool"], "preflight": [{"id": "benign-context", "verdict": "ALLOW"}]}],
    }
    text = run_agentdojo.render_markdown(summary)
    assert "| none | " in text and "| full-global | " in text
    assert "## By suite" in text and "workspace" in text
    assert "after enforcement" in text


def test_parse_args_rejects_unknown_arms():
    args = run_agentdojo.parse_args(["--arms", "none,full-task", "--dry-run"])
    assert args.arms == ["none", "full-task"] and args.dry_run is True
    with pytest.raises(SystemExit):
        run_agentdojo.parse_args(["--arms", "nope"])


def test_upstream_adapters_are_still_stubs():
    # Fails on purpose once implemented, as a reminder to update these tests.
    for call in (lambda: run_agentdojo.available_suites(),
                 lambda: run_agentdojo.build_pipeline(None, harness.ARMS["none"], "gpt-4o"),
                 lambda: run_agentdojo.run_case(None, "workspace", "user_task_0", None,
                                                harness.ARMS["none"], "tool_knowledge")):
        with pytest.raises(NotImplementedError):
            call()
