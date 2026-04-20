"""
Run the ACF-SDK benchmark harness.

Usage:
    python -m acf.benchmarks.run_benchmark
    python -m acf.benchmarks.run_benchmark --output results.json
    python -m acf.benchmarks.run_benchmark --backend sentence-transformer
"""

from __future__ import annotations

import argparse
import json
import sys

from acf.scanners import SemanticScanner, SemanticScannerConfig
from acf.benchmarks import BenchmarkRunner, build_full_dataset


def main():
    parser = argparse.ArgumentParser(description="ACF-SDK Benchmark Harness")
    parser.add_argument(
        "--backend",
        default="tfidf",
        choices=["tfidf", "sentence-transformer"],
        help="Embedding backend (default: tfidf)",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.60,
        help="Detection threshold (default: 0.60)",
    )
    parser.add_argument(
        "--block-threshold",
        type=float,
        default=0.85,
        help="Block threshold (default: 0.85)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Path to write JSON results (optional)",
    )
    args = parser.parse_args()

    # Build scanner
    config = SemanticScannerConfig(
        default_threshold=args.threshold,
        block_threshold=args.block_threshold,
    )
    scanner = SemanticScanner(config=config, backend=args.backend)

    # Build dataset
    dataset = build_full_dataset()

    # Run benchmark
    runner = BenchmarkRunner(scanner_fn=scanner.scan)
    report = runner.run(dataset)

    # Print report
    report.print_report()

    # Save JSON if requested
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report.to_dict(), f, indent=2)
        print(f"\n  Results saved to: {args.output}")

    # Exit code: 1 if F1 < 0.5 (basic quality gate)
    if report.f1 < 0.5:
        print(f"\n  WARNING: F1 score {report.f1:.4f} below quality gate (0.50)")
        sys.exit(1)


if __name__ == "__main__":
    main()
