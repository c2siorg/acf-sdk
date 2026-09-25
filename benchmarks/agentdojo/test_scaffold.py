"""Offline tests for the AgentDojo scaffold.

No network calls, no model API keys. These check the scaffold's shape --
condition registry, extension-point behaviour, and that build_pipeline
actually assembles a real AgentPipeline for C0 -- not AgentDojo's own
task/attack machinery, which needs a real model to exercise.

Run with: python3 -m pytest benchmarks/agentdojo/test_scaffold.py
(requires `pip install agentdojo` first, see README.md)
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SDK_ROOT = REPO_ROOT / "sdk" / "python"
for p in (SDK_ROOT, Path(__file__).resolve().parent):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

agentdojo = pytest.importorskip("agentdojo", reason="agentdojo not installed; see README.md")

from acf_pipeline import ACFPipelineElement, build_pipeline  # noqa: E402
from conditions import CONDITIONS  # noqa: E402


class DummyFirewall:
    """Stand-in for acf.Firewall -- no socket, no HMAC key required."""


class DummyLLM(agentdojo.agent_pipeline.base_pipeline_element.BasePipelineElement):
    name = "dummy-llm"

    def query(self, query, runtime, env=None, messages=(), extra_args=None):
        return query, runtime, env, messages, extra_args or {}


class TestConditionRegistry:
    def test_expected_conditions_present(self):
        assert set(CONDITIONS.keys()) == {"C0", "C1", "C3", "C4", "C5"}

    def test_c0_has_no_acf_hooks(self):
        assert CONDITIONS["C0"].acf_hooks == ()

    def test_c0_build_defense_returns_none(self):
        assert CONDITIONS["C0"].build_defense() is None

    @pytest.mark.parametrize("name", ["C1", "C3", "C4", "C5"])
    def test_unwired_conditions_raise_not_implemented(self, name):
        with pytest.raises(NotImplementedError, match=name):
            CONDITIONS[name].build_defense()

    def test_c1_is_prompt_only(self):
        assert CONDITIONS["C1"].acf_hooks == ("on_prompt",)

    def test_c3_is_content_path_only(self):
        assert CONDITIONS["C3"].acf_hooks == ("on_context",)

    def test_c4_is_tool_authorisation_layer(self):
        assert CONDITIONS["C4"].acf_hooks == ("on_tool_call",)

    def test_c5_is_full_acf(self):
        assert CONDITIONS["C5"].acf_hooks == ("on_prompt", "on_context", "on_tool_call")


class TestACFPipelineElement:
    def test_rejects_unknown_hook(self):
        with pytest.raises(ValueError, match="Unknown ACF hook"):
            ACFPipelineElement(DummyFirewall(), "on_nonsense")

    @pytest.mark.parametrize("hook", ["on_prompt", "on_context", "on_tool_call"])
    def test_constructs_for_each_known_hook(self, hook):
        element = ACFPipelineElement(DummyFirewall(), hook)
        assert element._hook == hook

    def test_query_is_a_scaffold_stub(self):
        element = ACFPipelineElement(DummyFirewall(), "on_prompt")
        with pytest.raises(NotImplementedError, match="scaffold stub"):
            element.query("hello", runtime=None)


class TestBuildPipeline:
    def test_c0_assembles_a_real_agent_pipeline(self):
        pipeline = build_pipeline(CONDITIONS["C0"], DummyLLM())
        assert isinstance(pipeline, agentdojo.agent_pipeline.agent_pipeline.AgentPipeline)
        # pipeline.name must keep the raw llm.name as a substring -- attacks
        # like important_instructions look it up via
        # get_model_name_from_pipeline, which requires a MODEL_NAMES key
        # (a real model string, or "local"/"vllm_parsed") inside pipeline.name.
        assert pipeline.name == "dummy-llm-C0"

    @pytest.mark.parametrize("name", ["C1", "C3", "C4", "C5"])
    def test_other_conditions_not_yet_wired(self, name):
        with pytest.raises(NotImplementedError):
            build_pipeline(CONDITIONS[name], DummyLLM())
