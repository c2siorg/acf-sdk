"""
Tests for the benchmark harness.

Covers:
- Dataset integrity (no missing fields, balanced labels)
- Benchmark runner produces valid report
- Metrics are mathematically correct
- Per-category breakdown works
- Latency stats are populated
- JSON export is valid
"""

from __future__ import annotations

import json

import pytest

from acf_sdk.benchmarks import (
    BenchmarkPayload,
    BenchmarkReport,
    BenchmarkRunner,
    PayloadLabel,
    build_benign_payloads,
    build_full_dataset,
    build_malicious_payloads,
)
from acf_sdk.scanners import (
    InputType,
    ScanAction,
    ScanInput,
    SemanticScanner,
    SemanticScannerConfig,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def scanner() -> SemanticScanner:
    config = SemanticScannerConfig(
        default_threshold=0.60,
        block_threshold=0.85,
    )
    return SemanticScanner(config=config, backend="tfidf")


@pytest.fixture(scope="module")
def full_dataset() -> list[BenchmarkPayload]:
    return build_full_dataset()


@pytest.fixture(scope="module")
def report(scanner, full_dataset) -> BenchmarkReport:
    runner = BenchmarkRunner(scanner_fn=scanner.scan)
    return runner.run(full_dataset)


# ---------------------------------------------------------------------------
# Dataset integrity
# ---------------------------------------------------------------------------


class TestDataset:
    def test_malicious_payloads_non_empty(self):
        payloads = build_malicious_payloads()
        assert len(payloads) >= 20

    def test_benign_payloads_non_empty(self):
        payloads = build_benign_payloads()
        assert len(payloads) >= 20

    def test_all_payloads_have_required_fields(self, full_dataset):
        for p in full_dataset:
            assert p.id
            assert p.text
            assert p.label in (PayloadLabel.MALICIOUS, PayloadLabel.BENIGN)
            assert p.category

    def test_unique_ids(self, full_dataset):
        ids = [p.id for p in full_dataset]
        assert len(ids) == len(set(ids))

    def test_has_multiple_categories(self):
        payloads = build_malicious_payloads()
        categories = set(p.category for p in payloads)
        assert len(categories) >= 5

    def test_has_hard_negatives(self):
        payloads = build_benign_payloads()
        hard_negatives = [p for p in payloads if p.category == "hard_negative"]
        assert len(hard_negatives) >= 5


# ---------------------------------------------------------------------------
# Benchmark report
# ---------------------------------------------------------------------------


class TestBenchmarkReport:
    def test_report_total_matches_dataset(self, report, full_dataset):
        assert report.total_payloads == len(full_dataset)

    def test_report_confusion_matrix_sums(self, report):
        total = (
            report.true_positives
            + report.false_positives
            + report.true_negatives
            + report.false_negatives
        )
        assert total == report.total_payloads

    def test_precision_between_0_and_1(self, report):
        assert 0.0 <= report.precision <= 1.0

    def test_recall_between_0_and_1(self, report):
        assert 0.0 <= report.recall <= 1.0

    def test_f1_between_0_and_1(self, report):
        assert 0.0 <= report.f1 <= 1.0

    def test_accuracy_between_0_and_1(self, report):
        assert 0.0 <= report.accuracy <= 1.0

    def test_category_metrics_populated(self, report):
        assert len(report.category_metrics) > 0
        for cat, m in report.category_metrics.items():
            assert m.total > 0
            assert 0.0 <= m.recall <= 1.0

    def test_latency_stats_populated(self, report):
        assert report.latency_mean_ms > 0
        assert report.latency_p50_ms > 0
        assert report.latency_p95_ms >= report.latency_p50_ms

    def test_low_false_positive_rate_on_normal_queries(self, scanner):
        """Normal queries should have a low false positive rate.

        NOTE: The TF-IDF backend has known FP on queries containing
        'What is/does' due to n-gram overlap with attack patterns like
        'What is your system prompt'. The sentence-transformer backend
        resolves this via semantic understanding. We assert FP rate < 30%
        for TF-IDF; production deployments should use sentence-transformer.
        """
        benign = [p for p in build_benign_payloads() if p.category == "normal"]
        runner = BenchmarkRunner(scanner_fn=scanner.scan)
        report = runner.run(benign)
        fp_rate = report.false_positives / report.total_benign if report.total_benign > 0 else 0
        assert fp_rate < 0.30, f"FP rate {fp_rate:.2%} exceeds 30% threshold"


# ---------------------------------------------------------------------------
# JSON export
# ---------------------------------------------------------------------------


class TestJsonExport:
    def test_to_dict_is_valid_json(self, report):
        d = report.to_dict()
        json_str = json.dumps(d)
        parsed = json.loads(json_str)
        assert "summary" in parsed
        assert "latency" in parsed
        assert "per_category" in parsed

    def test_summary_fields_present(self, report):
        d = report.to_dict()
        summary = d["summary"]
        for key in ["precision", "recall", "f1", "accuracy",
                     "true_positives", "false_positives",
                     "true_negatives", "false_negatives"]:
            assert key in summary


# ---------------------------------------------------------------------------
# Quality gate
# ---------------------------------------------------------------------------


class TestQualityGate:
    def test_f1_above_minimum(self, report):
        """The scanner should achieve at least 0.50 F1 on the benchmark."""
        assert report.f1 >= 0.50, (
            f"F1 score {report.f1:.4f} below quality gate. "
            f"Precision={report.precision:.4f}, Recall={report.recall:.4f}"
        )


# ---------------------------------------------------------------------------
# Policy matrix coverage
# ---------------------------------------------------------------------------


class TestPolicyMatrixCoverage:
    """Verify the dataset covers the v1 detection policies from the taxonomy matrix."""

    def test_covers_instruction_override(self):
        payloads = build_malicious_payloads()
        assert any(p.category == "instruction_override" for p in payloads)

    def test_covers_role_hijack(self):
        payloads = build_malicious_payloads()
        assert any(p.category == "role_hijack" for p in payloads)

    def test_covers_data_exfiltration(self):
        payloads = build_malicious_payloads()
        assert any(p.category == "data_exfiltration" for p in payloads)

    def test_covers_context_manipulation(self):
        payloads = build_malicious_payloads()
        cats = [p for p in payloads if p.input_type == InputType.RAG_DOCUMENT]
        assert len(cats) >= 2

    def test_covers_tool_abuse(self):
        payloads = build_malicious_payloads()
        cats = [p for p in payloads if p.input_type == InputType.TOOL_OUTPUT]
        assert len(cats) >= 2

    def test_covers_memory_poisoning(self):
        payloads = build_malicious_payloads()
        cats = [p for p in payloads if p.input_type == InputType.MEMORY_WRITE]
        assert len(cats) >= 2

    def test_benign_includes_all_input_types(self):
        payloads = build_benign_payloads()
        types = set(p.input_type for p in payloads)
        assert InputType.PROMPT in types
        assert InputType.RAG_DOCUMENT in types
        assert InputType.MEMORY_WRITE in types


# ---------------------------------------------------------------------------
# Dataset balance
# ---------------------------------------------------------------------------


class TestDatasetBalance:
    def test_roughly_balanced(self, full_dataset):
        mal = sum(1 for p in full_dataset if p.label == PayloadLabel.MALICIOUS)
        ben = sum(1 for p in full_dataset if p.label == PayloadLabel.BENIGN)
        ratio = mal / ben if ben > 0 else float("inf")
        assert 0.5 <= ratio <= 2.0, f"Dataset imbalanced: {mal} malicious, {ben} benign"

    def test_hard_negatives_exist(self, full_dataset):
        hard_neg = [p for p in full_dataset if p.category == "hard_negative"]
        assert len(hard_neg) >= 5, "Need sufficient hard negatives to test precision"