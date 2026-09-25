from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).with_name("run_asb.py")
SPEC = importlib.util.spec_from_file_location("run_asb", MODULE_PATH)
assert SPEC and SPEC.loader
run_asb = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = run_asb
SPEC.loader.exec_module(run_asb)

from common import harness  # noqa: E402


def record(arm: str, attack_type: str, succeeded: bool, **extra) -> dict:
    return {
        "attack_type": attack_type, "agent": "agent_0", "case_id": "c0", "arm": arm,
        "attack_succeeded": succeeded, "refused": False, "benign_success": None,
        "intercepted_at": None, "verdicts": [], "error": None, **extra,
    }


def test_compute_scores_reports_asr_refusals_and_benign_success():
    records = [
        record("none", "direct_prompt_injection", True),
        record("none", "direct_prompt_injection", False, refused=True),
        record("none", "memory_poisoning", False, benign_success=True),
        record("none", "memory_poisoning", True, benign_success=False),
    ]
    overall = run_asb.compute_scores(records)["none"]["overall"]
    assert overall["cases"] == 4
    assert overall["asr"] == 0.5
    assert overall["refuse_rate"] == 0.25
    assert overall["benign_success"] == 0.5


def test_compute_scores_counts_where_attacks_were_intercepted():
    records = [
        record("full-global", "observation_prompt_injection", False, intercepted_at="on_context"),
        record("full-global", "observation_prompt_injection", False, intercepted_at="on_tool_call"),
        record("full-global", "observation_prompt_injection", True),
    ]
    group = run_asb.compute_scores(records)["full-global"]["attack_types"]["observation_prompt_injection"]
    assert group["intercepted_at"] == {"not_intercepted": 1, "on_context": 1, "on_tool_call": 1}
    assert group["asr"] == pytest.approx(1 / 3)


def test_compute_scores_ignores_errored_cases_but_counts_them():
    records = [
        record("none", "mixed", True),
        record("none", "mixed", False, error="model error"),
    ]
    scores = run_asb.compute_scores(records)["none"]
    assert scores["overall"]["cases"] == 1 and scores["errors"] == 1


def test_benign_success_is_none_when_no_benign_task_ran():
    records = [record("none", "pot_backdoor", True)]
    assert run_asb.compute_scores(records)["none"]["overall"]["benign_success"] is None


def test_every_attack_type_maps_to_an_expected_hook():
    assert set(run_asb.EXPECTED_HOOK) == set(run_asb.ATTACK_TYPES)


def test_check_clone_requires_pin_then_clone_then_matching_head(tmp_path, monkeypatch):
    with pytest.raises(SystemExit, match="no pinned ASB commit"):
        run_asb.check_clone({"repository": "agiresearch/ASB", "commit": None}, tmp_path / "ASB")

    manifest = {"repository": "agiresearch/ASB", "commit": "a" * 40}
    with pytest.raises(SystemExit, match="does not exist"):
        run_asb.check_clone(manifest, tmp_path / "missing")

    clone = tmp_path / "ASB"
    clone.mkdir()
    monkeypatch.setattr(subprocess, "check_output", lambda *a, **k: "b" * 40 + "\n")
    with pytest.raises(SystemExit, match="pins"):
        run_asb.check_clone(manifest, clone)

    monkeypatch.setattr(subprocess, "check_output", lambda *a, **k: "a" * 40 + "\n")
    assert run_asb.check_clone(manifest, clone) == "a" * 40


def test_render_markdown_shows_arms_and_attack_classes():
    summary = {
        "provenance": {"mode": "hooks", "model": "gpt-4o", "semantic_scanner": "off",
                       "acf_commit": "abc", "asb_commit": "def"},
        "scores": run_asb.compute_scores([
            record("none", "direct_prompt_injection", True),
            record("full-global", "direct_prompt_injection", False, intercepted_at="on_tool_call"),
        ]),
        "sidecars": [],
    }
    text = run_asb.render_markdown(summary)
    assert "| none |" in text and "| full-global |" in text
    assert "## By attack class" in text and "on_tool_call=1" in text
    assert "only `agent` mode gives ASR" in text


def test_parse_args_validates_arms_and_attack_types():
    args = run_asb.parse_args(["--attack-types", "memory_poisoning", "--arms", "detect", "--dry-run"])
    assert args.attack_types == ["memory_poisoning"] and args.arms == ["detect"]
    with pytest.raises(SystemExit):
        run_asb.parse_args(["--attack-types", "not_an_attack"])
    with pytest.raises(SystemExit):
        run_asb.parse_args(["--arms", "nope"])


def test_upstream_adapters_are_still_stubs(tmp_path):
    with pytest.raises(NotImplementedError):
        run_asb.load_cases(tmp_path, "direct_prompt_injection", None)
    with pytest.raises(NotImplementedError):
        run_asb.run_case(None, "hooks", harness.ARMS["none"], {"case_id": "c0"}, "gpt-4o")
