"""
Adversarial Benchmark Harness for the ACF-SDK Scan Pipeline.

Evaluates scanner performance against curated attack and benign datasets,
producing detection metrics (precision, recall, F1), per-category breakdowns,
latency statistics, and a summary report.

This harness is scanner-agnostic — it accepts any callable that takes a
ScanInput and returns a result with an `action` field. This means it can
benchmark the lexical scanner, semantic scanner, or the full pipeline
once integrated.

Usage:
    python -m acf.benchmarks.run_benchmark
    python -m acf.benchmarks.run_benchmark --output results.json
"""

from __future__ import annotations

import json
import logging
import statistics
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional, Any

from acf.scanners.models import InputType, ScanAction, ScanInput, TrustLevel

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Benchmark dataset model
# ---------------------------------------------------------------------------


class PayloadLabel(str, Enum):
    """Ground truth label for a benchmark payload."""
    MALICIOUS = "malicious"
    BENIGN = "benign"


@dataclass
class BenchmarkPayload:
    """A single test case for the benchmark."""
    id: str
    text: str
    label: PayloadLabel
    category: str = "unknown"
    input_type: InputType = InputType.PROMPT
    description: str = ""


@dataclass
class ScanResult:
    """Result of scanning a single payload."""
    payload_id: str
    label: PayloadLabel
    category: str
    predicted_malicious: bool
    risk_score: float
    action: str
    latency_ms: float
    hits: List[Dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


@dataclass
class CategoryMetrics:
    """Metrics for a single attack category."""
    category: str
    total: int = 0
    true_positives: int = 0
    false_negatives: int = 0
    avg_risk_score: float = 0.0
    avg_latency_ms: float = 0.0

    @property
    def recall(self) -> float:
        if self.total == 0:
            return 0.0
        return self.true_positives / self.total


@dataclass
class BenchmarkReport:
    """Full benchmark report with aggregate and per-category metrics."""
    # Aggregate
    total_payloads: int = 0
    total_malicious: int = 0
    total_benign: int = 0
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0

    # Per-category
    category_metrics: Dict[str, CategoryMetrics] = field(default_factory=dict)

    # Latency
    latency_p50_ms: float = 0.0
    latency_p95_ms: float = 0.0
    latency_p99_ms: float = 0.0
    latency_mean_ms: float = 0.0

    # All results
    results: List[ScanResult] = field(default_factory=list)

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def accuracy(self) -> float:
        if self.total_payloads == 0:
            return 0.0
        return (self.true_positives + self.true_negatives) / self.total_payloads

    def to_dict(self) -> dict:
        return {
            "summary": {
                "total_payloads": self.total_payloads,
                "total_malicious": self.total_malicious,
                "total_benign": self.total_benign,
                "true_positives": self.true_positives,
                "false_positives": self.false_positives,
                "true_negatives": self.true_negatives,
                "false_negatives": self.false_negatives,
                "precision": round(self.precision, 4),
                "recall": round(self.recall, 4),
                "f1": round(self.f1, 4),
                "accuracy": round(self.accuracy, 4),
            },
            "latency": {
                "mean_ms": round(self.latency_mean_ms, 2),
                "p50_ms": round(self.latency_p50_ms, 2),
                "p95_ms": round(self.latency_p95_ms, 2),
                "p99_ms": round(self.latency_p99_ms, 2),
            },
            "per_category": {
                cat: {
                    "total": m.total,
                    "true_positives": m.true_positives,
                    "false_negatives": m.false_negatives,
                    "recall": round(m.recall, 4),
                    "avg_risk_score": round(m.avg_risk_score, 4),
                    "avg_latency_ms": round(m.avg_latency_ms, 2),
                }
                for cat, m in self.category_metrics.items()
            },
        }

    def print_report(self) -> None:
        d = self.to_dict()
        s = d["summary"]
        l = d["latency"]

        print("\n" + "=" * 60)
        print("  ACF-SDK BENCHMARK REPORT")
        print("=" * 60)

        print(f"\n  Payloads:  {s['total_payloads']} "
              f"({s['total_malicious']} malicious, {s['total_benign']} benign)")
        print(f"  TP: {s['true_positives']}  FP: {s['false_positives']}  "
              f"TN: {s['true_negatives']}  FN: {s['false_negatives']}")

        print(f"\n  Precision: {s['precision']:.4f}")
        print(f"  Recall:    {s['recall']:.4f}")
        print(f"  F1 Score:  {s['f1']:.4f}")
        print(f"  Accuracy:  {s['accuracy']:.4f}")

        print(f"\n  Latency — mean: {l['mean_ms']:.2f}ms  "
              f"p50: {l['p50_ms']:.2f}ms  "
              f"p95: {l['p95_ms']:.2f}ms  "
              f"p99: {l['p99_ms']:.2f}ms")

        if d["per_category"]:
            print(f"\n  {'Category':<25} {'Total':>5} {'TP':>5} {'FN':>5} "
                  f"{'Recall':>8} {'Avg Score':>10} {'Avg ms':>8}")
            print("  " + "-" * 72)
            for cat, m in d["per_category"].items():
                print(f"  {cat:<25} {m['total']:>5} {m['true_positives']:>5} "
                      f"{m['false_negatives']:>5} {m['recall']:>8.4f} "
                      f"{m['avg_risk_score']:>10.4f} {m['avg_latency_ms']:>8.2f}")

        print("\n" + "=" * 60)


# ---------------------------------------------------------------------------
# Benchmark runner
# ---------------------------------------------------------------------------


class BenchmarkRunner:
    """
    Runs a scanner against a dataset and produces a BenchmarkReport.

    The scanner_fn must accept a ScanInput and return an object with:
    - action: ScanAction (or string)
    - risk_score: float
    - semantic_hits: list (optional)
    - processing_time_ms: float (optional)
    """

    def __init__(
        self,
        scanner_fn: Callable[[ScanInput], Any],
        block_actions: Optional[List[str]] = None,
    ) -> None:
        self._scanner_fn = scanner_fn
        self._block_actions = block_actions or [
            ScanAction.SHORT_CIRCUIT_BLOCK,
            ScanAction.SHORT_CIRCUIT_BLOCK.value,
        ]

    def run(self, payloads: List[BenchmarkPayload]) -> BenchmarkReport:
        """Run the benchmark and return the report."""
        report = BenchmarkReport()
        report.total_payloads = len(payloads)
        latencies: List[float] = []

        for payload in payloads:
            scan_input = ScanInput(
                agent_id="benchmark",
                execution_id="bench-001",
                session_id="bench-sess",
                input_type=payload.input_type,
                normalized_content=payload.text,
                trust_level=TrustLevel.LOW,
            )

            t0 = time.perf_counter()
            result = self._scanner_fn(scan_input)
            elapsed_ms = (time.perf_counter() - t0) * 1000

            action_str = str(result.action.value if hasattr(result.action, "value") else result.action)
            predicted_malicious = action_str in [str(a) for a in self._block_actions]

            # Also count as malicious if risk_score exceeds a reasonable threshold
            # and there are semantic hits (for scanners that return PROCEED with high risk)
            risk_score = getattr(result, "risk_score", 0.0)
            hits = []
            if hasattr(result, "semantic_hits"):
                hits = [
                    {"category": h.matched_category, "score": h.similarity_score}
                    for h in result.semantic_hits
                ]
                if len(result.semantic_hits) > 0 and risk_score >= 0.70:
                    predicted_malicious = True

            scan_result = ScanResult(
                payload_id=payload.id,
                label=payload.label,
                category=payload.category,
                predicted_malicious=predicted_malicious,
                risk_score=risk_score,
                action=action_str,
                latency_ms=round(elapsed_ms, 3),
                hits=hits,
            )
            report.results.append(scan_result)
            latencies.append(elapsed_ms)

            # Confusion matrix
            if payload.label == PayloadLabel.MALICIOUS:
                report.total_malicious += 1
                if predicted_malicious:
                    report.true_positives += 1
                else:
                    report.false_negatives += 1

                # Per-category tracking
                cat = payload.category
                if cat not in report.category_metrics:
                    report.category_metrics[cat] = CategoryMetrics(category=cat)
                cm = report.category_metrics[cat]
                cm.total += 1
                if predicted_malicious:
                    cm.true_positives += 1
                else:
                    cm.false_negatives += 1

            else:
                report.total_benign += 1
                if predicted_malicious:
                    report.false_positives += 1
                else:
                    report.true_negatives += 1

        # Per-category averages
        for cat, cm in report.category_metrics.items():
            cat_results = [r for r in report.results if r.category == cat]
            if cat_results:
                cm.avg_risk_score = statistics.mean(r.risk_score for r in cat_results)
                cm.avg_latency_ms = statistics.mean(r.latency_ms for r in cat_results)

        # Latency stats
        if latencies:
            latencies.sort()
            report.latency_mean_ms = statistics.mean(latencies)
            report.latency_p50_ms = latencies[len(latencies) // 2]
            report.latency_p95_ms = latencies[int(len(latencies) * 0.95)]
            report.latency_p99_ms = latencies[int(len(latencies) * 0.99)]

        return report
