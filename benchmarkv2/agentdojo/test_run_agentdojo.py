from __future__ import annotations

import importlib.util
import sys
from types import SimpleNamespace
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
    assert run_agentdojo.parse_args(["--injection-limit", "1"]).injection_limit == 1
    with pytest.raises(SystemExit, match="--injection-limit must be positive"):
        run_agentdojo.parse_args(["--injection-limit", "0"])
    assert run_agentdojo.parse_args([]).max_api_calls == 20
    with pytest.raises(SystemExit, match="--max-api-calls must be positive"):
        run_agentdojo.parse_args(["--max-api-calls", "0"])


def test_openai_api_budget_counts_attempts_and_disables_client_retries():
    calls = []
    completions = SimpleNamespace(create=lambda **kwargs: calls.append(kwargs))

    class Client:
        chat = SimpleNamespace(completions=completions)

        def with_options(self, **kwargs):
            assert kwargs == {"max_retries": 0, "timeout": 45.0}
            return self

    budget = run_agentdojo.ApiAttemptBudget(1)
    client = run_agentdojo.cap_openai_client(Client(), budget)
    client.chat.completions.create(model="gpt-4o-2024-08-06")
    with pytest.raises(harness.BudgetExceeded, match="cap of 1"):
        client.chat.completions.create(model="gpt-4o-2024-08-06")
    assert budget.used == 1
    assert len(calls) == 1


def test_api_budget_caps_output_and_records_actual_usage():
    requests = []

    def create(**kwargs):
        requests.append(kwargs)
        return SimpleNamespace(
            model="gpt-4o-2024-11-20",
            usage=SimpleNamespace(prompt_tokens=150, completion_tokens=30),
        )

    client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    client.with_options = lambda **kwargs: client
    budget = run_agentdojo.ApiAttemptBudget(2, max_output_tokens=512)
    capped = run_agentdojo.cap_openai_client(client, budget)
    capped.chat.completions.create(model="gpt-4o", max_tokens=999)
    assert requests[0]["max_tokens"] == 512
    assert budget.prompt_tokens == 150
    assert budget.completion_tokens == 30
    assert budget.response_models == {"gpt-4o-2024-11-20"}


def test_azure_model_uses_deployment_and_preserves_checkpoint(monkeypatch):
    pytest.importorskip("agentdojo")
    import openai
    from agentdojo.attacks.base_attacks import MODEL_NAMES

    calls = []
    client = object()

    def azure_client(**kwargs):
        calls.append(kwargs)
        return client

    monkeypatch.setattr(openai, "AzureOpenAI", azure_client)
    llm = run_agentdojo.build_model("gpt-4o-2024-11-20", azure_deployment="gpt-4o")
    assert llm.client is client
    assert llm.model == "gpt-4o"
    assert calls == [{"api_version": "2024-10-21"}]
    assert MODEL_NAMES["gpt-4o-2024-11-20"] == MODEL_NAMES["gpt-4o-2024-05-13"]


def test_azure_and_output_limit_arguments():
    args = run_agentdojo.parse_args(["--azure-deployment", "gpt-4o", "--max-output-tokens", "512"])
    assert args.azure_deployment == "gpt-4o"
    assert args.max_output_tokens == 512
    with pytest.raises(SystemExit, match="--max-output-tokens must be positive"):
        run_agentdojo.parse_args(["--max-output-tokens", "0"])
    with pytest.raises(SystemExit, match="cannot be combined"):
        run_agentdojo.parse_args(["--azure-deployment", "gpt-4o", "--base-url", "http://localhost"])


def test_ambient_openai_endpoint_is_rejected_before_a_live_run(monkeypatch):
    monkeypatch.setenv("OPENAI_BASE_URL", "https://private-endpoint.invalid/secret-value")
    with pytest.raises(SystemExit, match="pass --base-url explicitly") as exc:
        run_agentdojo.main([])
    assert "private-endpoint" not in str(exc.value)
    assert "secret-value" not in str(exc.value)


def test_prebuilt_model_cannot_bypass_api_budget():
    pytest.importorskip("agentdojo")
    with pytest.raises(ValueError, match="budgeted pipelines require a model ID"):
        run_agentdojo.build_pipeline(
            None, harness.ARMS["none"], object(), budget=run_agentdojo.ApiAttemptBudget(1)
        )


def test_available_suites_come_from_the_installed_registry():
    pytest.importorskip("agentdojo")
    assert set(run_agentdojo.available_suites()) == {"workspace", "travel", "banking", "slack"}


def test_task_selection_is_numerically_ordered_and_limited():
    assert run_agentdojo.select_task_ids(
        ["user_task_9", "user_task_2", "user_task_0"], limit=2
    ) == ["user_task_0", "user_task_2"]
    with pytest.raises(ValueError, match="positive"):
        run_agentdojo.select_task_ids(["user_task_0"], limit=0)


def test_injection_limit_caps_direct_attacks_and_preserves_effective_dos_task():
    injection_tasks = {
        "injection_task_9": None,
        "injection_task_2": None,
        "injection_task_0": None,
    }
    assert run_agentdojo.select_injection_task_ids(injection_tasks) == [
        "injection_task_0", "injection_task_2", "injection_task_9"
    ]
    assert run_agentdojo.select_injection_task_ids(injection_tasks, limit=1) == [
        "injection_task_0"
    ]
    assert run_agentdojo.select_injection_task_ids(
        injection_tasks, limit=1, is_dos=True
    ) == ["injection_task_9"]
    with pytest.raises(ValueError, match="injection limit must be positive"):
        run_agentdojo.select_injection_task_ids(injection_tasks, limit=0)


def test_task_scope_uses_ground_truth_tool_names_and_fails_if_missing():
    task = SimpleNamespace(
        init_environment=lambda env: env,
        ground_truth=lambda env: [SimpleNamespace(function="search"), SimpleNamespace(function="send")],
    )
    suite = SimpleNamespace(
        tools=[SimpleNamespace(name="send"), SimpleNamespace(name="search"), SimpleNamespace(name="other")],
        get_user_task_by_id=lambda task_id: task,
        load_and_inject_default_environment=lambda injections: object(),
    )
    assert run_agentdojo.task_tool_names(suite, "user_task_0") == ("search", "send")

    suite.get_user_task_by_id = lambda task_id: SimpleNamespace(
        init_environment=lambda env: env,
        ground_truth=lambda env: [],
    )
    with pytest.raises(ValueError, match="cannot derive task-scoped tools"):
        run_agentdojo.task_tool_names(suite, "user_task_1")


def test_model_default_preserves_checkpoint_and_attack_prompt_family(monkeypatch):
    pytest.importorskip("agentdojo")
    import agentdojo.agent_pipeline.agent_pipeline as agent_pipeline
    from agentdojo.attacks.base_attacks import MODEL_NAMES

    calls = []
    llm = object()

    def fake_get_llm(provider, model, model_id, tool_delimiter):
        calls.append((provider, model, model_id, tool_delimiter))
        return llm

    monkeypatch.setattr(agent_pipeline, "get_llm", fake_get_llm)
    assert run_agentdojo.DEFAULT_MODEL == "gpt-4o-2024-08-06"
    assert run_agentdojo.model_provider_for(run_agentdojo.DEFAULT_MODEL) == "openai"
    assert run_agentdojo.build_model(run_agentdojo.DEFAULT_MODEL) is llm
    assert calls == [("openai", "gpt-4o-2024-08-06", None, "tool")]
    assert MODEL_NAMES[run_agentdojo.DEFAULT_MODEL] == MODEL_NAMES["gpt-4o-2024-05-13"]
    with pytest.raises(ValueError, match="not supported by AgentDojo 0.1.35"):
        run_agentdojo.model_provider_for("not-a-registered-agentdojo-model")


class FakeFirewall:
    def __init__(self, tool_decision, context_decision, sanitized_text="redacted"):
        self.tool_decision = tool_decision
        self.context_decision = context_decision
        self.sanitized_text = sanitized_text
        self.context_inputs = []

    def on_tool_call(self, name, params):
        if self.tool_decision == harness.Decision.SANITISE:
            return SimpleNamespace(decision=self.tool_decision, sanitised_text=self.sanitized_text)
        return self.tool_decision

    def on_context(self, chunks):
        self.context_inputs.extend(chunks)
        return [SimpleNamespace(decision=self.context_decision, sanitised_text=self.sanitized_text)]


class FakeRuntime:
    def __init__(self, error="secret tool error"):
        self.functions = {"send_email": SimpleNamespace(name="send_email")}
        self.calls = []
        self.error = error

    def run_function(self, env, function, args):
        self.calls.append((function, args))
        return "secret tool output", self.error


def query_with_tool_call(executor, runtime):
    call = SimpleNamespace(function="send_email", args={"body": "secret args"}, id="call-1")
    messages = [{"role": "assistant", "tool_calls": [call]}]
    return executor.query("task", runtime, env=object(), messages=messages)


@pytest.mark.parametrize("decision", [harness.Decision.BLOCK, harness.Decision.SANITISE])
def test_denied_or_unreconstructable_sanitized_call_never_executes(decision):
    pytest.importorskip("agentdojo")
    firewall = FakeFirewall(decision, harness.Decision.ALLOW)
    trace = run_agentdojo.CaseTrace()
    executor = run_agentdojo.tools_executor_class()(firewall, harness.ARMS["gate-global"], trace)
    runtime = FakeRuntime(error=None)

    from agentdojo.agent_pipeline.errors import AbortAgentError

    with pytest.raises(AbortAgentError) as exc:
        query_with_tool_call(executor, runtime)
    assert runtime.calls == []
    assert trace.tool_call_verdicts[0]["execution_attempted"] is False
    assert trace.tool_call_verdicts[0]["verdict"] == decision.name
    assert "secret args" not in repr(exc.value.messages)
    if decision == harness.Decision.SANITISE:
        assert trace.sanitised_tool_calls_not_executed == 1


def test_context_sanitise_replaces_tool_output_and_error_before_return():
    pytest.importorskip("agentdojo")
    firewall = FakeFirewall(harness.Decision.ALLOW, harness.Decision.SANITISE)
    trace = run_agentdojo.CaseTrace()
    executor = run_agentdojo.tools_executor_class()(firewall, harness.ARMS["full-global"], trace)
    runtime = FakeRuntime()

    *_, messages, _ = query_with_tool_call(executor, runtime)
    tool_message = messages[-1]
    assert firewall.context_inputs == ["secret tool output\nsecret tool error"]
    assert tool_message["content"][0]["content"] == "redacted"
    assert tool_message["error"] is None
    assert "secret tool output" not in repr(messages)
    assert "secret tool error" not in repr(messages)
    assert trace.observation_verdicts[0]["verdict"] == "SANITISE"


def test_context_block_withholds_tool_output_and_error():
    pytest.importorskip("agentdojo")
    firewall = FakeFirewall(harness.Decision.ALLOW, harness.Decision.BLOCK)
    trace = run_agentdojo.CaseTrace()
    executor = run_agentdojo.tools_executor_class()(firewall, harness.ARMS["detect"], trace)
    runtime = FakeRuntime()

    *_, messages, _ = query_with_tool_call(executor, runtime)
    tool_message = messages[-1]
    assert tool_message["content"][0]["content"] == harness.WITHHELD_OBSERVATION
    assert tool_message["error"] is None
    assert "secret tool output" not in repr(messages)
    assert "secret tool error" not in repr(messages)


class FakeSuite:
    name = "workspace"

    def __init__(self, result=(True, False), error=None):
        self.user_tasks = {"user_task_0": SimpleNamespace(ID="user_task_0")}
        self.injection_tasks = {
            "injection_task_0": SimpleNamespace(ID="injection_task_0"),
            "injection_task_1": SimpleNamespace(ID="injection_task_1"),
        }
        self.result = result
        self.error = error
        self.calls = []

    def get_user_task_by_id(self, task_id):
        return self.user_tasks[task_id]

    def get_injection_task_by_id(self, task_id):
        return self.injection_tasks[task_id]

    def run_task_with_pipeline(self, pipeline, user_task, injection_task, injections):
        self.calls.append((user_task.ID, getattr(injection_task, "ID", None), injections))
        if self.error:
            raise self.error
        return self.result


def test_run_case_uses_upstream_suite_evaluator_and_records_dos_task(monkeypatch):
    pytest.importorskip("agentdojo")

    class Attack:
        is_dos_attack = True

        def attack(self, user_task, injection_task):
            return {"effective": injection_task.ID}

    monkeypatch.setattr(run_agentdojo, "load_attack", lambda *args: Attack())
    suite = FakeSuite(result=(False, True))
    pipeline = SimpleNamespace(_acf_trace=run_agentdojo.CaseTrace())
    record = run_agentdojo.run_case(
        pipeline, suite, "user_task_0", "injection_task_1", harness.ARMS["none"], "dos"
    )
    assert suite.calls == [("user_task_0", "injection_task_0", {"effective": "injection_task_0"})]
    assert record["requested_injection_task"] == "injection_task_1"
    assert record["effective_injection_task"] == "injection_task_0"
    assert record["attack_succeeded"] is True
    assert "DoS" in record["attack_success_source"]


def test_run_case_errors_are_not_scored_as_attack_results(monkeypatch):
    pytest.importorskip("agentdojo")

    class Attack:
        is_dos_attack = False

        def attack(self, user_task, injection_task):
            return {}

    monkeypatch.setattr(run_agentdojo, "load_attack", lambda *args: Attack())
    suite = FakeSuite(error=RuntimeError("provider key must not appear"))
    pipeline = SimpleNamespace(_acf_trace=run_agentdojo.CaseTrace())
    record = run_agentdojo.run_case(
        pipeline, suite, "user_task_0", "injection_task_0", harness.ARMS["none"], "direct"
    )
    assert record["utility"] is None and record["attack_succeeded"] is None
    assert record["error"] == "RuntimeError"
    assert "provider key" not in repr(record)
    assert run_agentdojo.compute_scores([record]) == {}


def test_run_case_propagates_api_budget_exhaustion():
    pytest.importorskip("agentdojo")
    suite = FakeSuite(error=harness.BudgetExceeded("API attempt cap reached"))
    pipeline = SimpleNamespace(_acf_trace=run_agentdojo.CaseTrace())
    with pytest.raises(harness.BudgetExceeded, match="API attempt cap reached"):
        run_agentdojo.run_case(
            pipeline, suite, "user_task_0", None, harness.ARMS["none"], "tool_knowledge"
        )
