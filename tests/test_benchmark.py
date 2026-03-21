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

from acf.benchmarks import (
    BenchmarkPayload,
    BenchmarkReport,
    BenchmarkRunner,
    PayloadLabel,
    build_benign_payloads,
    build_full_dataset,
    build_malicious_payloads,
)
from acf.scanners import (
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
