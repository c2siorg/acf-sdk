from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).with_name("run_overhead.py")
SPEC = importlib.util.spec_from_file_location("run_overhead", MODULE_PATH)
assert SPEC and SPEC.loader
run_overhead = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = run_overhead  # dataclasses resolve annotations through sys.modules
SPEC.loader.exec_module(run_overhead)


GO_BENCH_SAMPLE = """\
goos: windows
goarch: amd64
pkg: github.com/acf-sdk/sidecar/internal/pipeline
cpu: Intel(R) Core(TM) Ultra 7 255U
BenchmarkStage/validate/corpus-14   	 1000000	      2100 ns/op	     128 B/op	       1 allocs/op
BenchmarkStage/validate/corpus-14   	 1000000	      1900 ns/op	     128 B/op	       1 allocs/op
BenchmarkNormaliseAdversarial/base64-depth=1/size=4096-14   	 100	    170700 ns/op	  24.00 MB/s	   86904 B/op	     203 allocs/op
PASS
ok  	github.com/acf-sdk/sidecar/internal/pipeline	22.445s
pkg: github.com/acf-sdk/sidecar/internal/crypto
BenchmarkNonceStoreSeen/stored=0-14         	 5000000	      240 ns/op	     64 B/op	       2 allocs/op
"""


def test_percentile_interpolates_between_ranks():
    assert run_overhead.percentile([1, 2, 3, 4], 0.5) == 2.5
    assert run_overhead.percentile([5], 0.99) == 5
    assert run_overhead.percentile([], 0.5) is None


def test_summarize_ns_reports_milliseconds():
    summary = run_overhead.summarize_ns([3_000_000, 1_000_000])
    assert summary["count"] == 2
    assert summary["p50_ms"] == 2.0
    assert summary["max_ms"] == 3.0
    assert run_overhead.summarize_ns([]) == {"count": 0}


def test_spread_ignores_missing_repetitions():
    assert run_overhead.spread([None, 1.0, 3.0, 2.0]) == {"median": 2.0, "min": 1.0, "max": 3.0, "n": 3}
    assert run_overhead.spread([None]) is None


def test_parse_go_bench_groups_runs_by_package_and_name():
    parsed = run_overhead.parse_go_bench(GO_BENCH_SAMPLE)
    assert parsed["pipeline/BenchmarkStage/validate/corpus"]["ns_per_op"] == [2100.0, 1900.0]
    adversarial = parsed["pipeline/BenchmarkNormaliseAdversarial/base64-depth=1/size=4096"]
    assert adversarial["mb_per_s"] == [24.0]
    assert adversarial["allocs_per_op"] == [203.0]
    assert parsed["crypto/BenchmarkNonceStoreSeen/stored=0"]["bytes_per_op"] == [64.0]

    summary = run_overhead.summarize_go_bench(parsed)
    assert summary["pipeline/BenchmarkStage/validate/corpus"]["ns_per_op"]["median"] == 2000.0
    assert "mb_per_s" not in summary["pipeline/BenchmarkStage/validate/corpus"]


def test_timing_summary_counts_sanitise_only_where_it_ran():
    record = {
        "read_ns": 10, "verify_ns": 20, "nonce_ns": 30, "unmarshal_ns": 40, "policy_ns": 50,
        "log_ns": 60, "write_ns": 70, "total_ns": 1000, "sanitise_ns": 0,
        "stages_ns": {"validate": 1, "normalise": 2, "scan": 3, "aggregate": 4},
    }
    summary = run_overhead.timing_summary([record, {**record, "sanitise_ns": 500}])
    assert summary["policy"]["count"] == 2
    assert summary["sanitise"]["count"] == 1
    assert summary["scan"]["p50_ms"] == 3e-6


def test_build_payload_timed_matches_sdk_bytes(monkeypatch):
    monkeypatch.delenv("ACF_SEMANTIC_SCAN", raising=False)
    firewall = run_overhead.Firewall(socket_path="unused", hmac_key=b"k" * 32, enable_semantic_scan=False)
    for case in run_overhead.load_corpus():
        hook = case["hook_type"]
        content = run_overhead.sdk_content(case)
        payload, scan_ns, serialise_ns = run_overhead.build_payload_timed(firewall, hook, content)
        assert payload == firewall._build_payload(hook, content, provenance=run_overhead.SDK_PROVENANCE[hook])
        assert scan_ns >= 0 and serialise_ns >= 0


class RecordingFirewall:
    def __init__(self):
        self.calls = []

    def on_prompt(self, text):
        self.calls.append(("on_prompt", text))

    def on_context(self, chunks):
        self.calls.append(("on_context", chunks))

    def on_tool_call(self, name, params):
        self.calls.append(("on_tool_call", name, params))

    def on_memory(self, key, value, op):
        self.calls.append(("on_memory", key, value, op))


def test_public_call_reaches_the_matching_hook_for_every_corpus_case():
    corpus = run_overhead.load_corpus()
    firewall = RecordingFirewall()
    for case in corpus:
        run_overhead.public_call(firewall, case)
    assert [call[0] for call in firewall.calls] == [case["hook_type"] for case in corpus]
    for call in firewall.calls:
        if call[0] == "on_context":
            assert isinstance(call[1], list) and isinstance(call[1][0], str)
        if call[0] == "on_tool_call":
            assert isinstance(call[2], dict)


def test_load_conditions_have_unique_names_and_quick_scales_down():
    full = run_overhead.load_conditions(quick=False)
    quick = run_overhead.load_conditions(quick=True)
    assert len({c.name for c in full}) == len(full)
    assert [c.name for c in full] == [c.name for c in quick]
    assert all(q.requests < f.requests for f, q in zip(full, quick))


def test_open_loop_rates_are_fractions_of_peak():
    conditions = run_overhead.open_loop_conditions(1000.0, quick=False)
    assert [c.rate for c in conditions] == [250.0, 500.0, 750.0, 900.0]
    assert [c.requests for c in conditions] == [2500, 5000, 7500, 9000]
    assert all(c.mode == "open" for c in conditions)


def test_peak_throughput_ignores_ablations_and_open_loop():
    runs = [
        {"mode": "closed", "workload": "corpus", "timing_log": True, "stderr": "file", "throughput_rps": 900.0},
        {"mode": "closed", "workload": "corpus", "timing_log": False, "stderr": "file", "throughput_rps": 5000.0},
        {"mode": "open", "workload": "corpus", "timing_log": True, "stderr": "file", "throughput_rps": 7000.0},
        {"mode": "closed", "workload": "corpus", "timing_log": True, "stderr": "file", "throughput_rps": 1200.0},
    ]
    assert run_overhead.peak_throughput(runs) == 1200.0
    with pytest.raises(RuntimeError):
        run_overhead.peak_throughput([])


def test_render_markdown_handles_a_partial_summary():
    summary = {
        "provenance": {"acf_commit": "abc", "machine": {"cpu": "test cpu"}},
        "quick": True,
        "go_bench": {
            "command": "go test -bench .",
            "benchmarks": run_overhead.summarize_go_bench(run_overhead.parse_go_bench(GO_BENCH_SAMPLE)),
        },
    }
    text = run_overhead.render_markdown(summary)
    assert "## Go benchmarks" in text
    assert "not reportable" in text
    assert "## Python SDK" not in text
