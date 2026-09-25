#!/usr/bin/env python3
"""Measure the runtime overhead ACF adds to an agent, on the local machine.

Backs the runtime overhead section of the paper. Three parts, each written
under results/<UTC timestamp>-<os>-<arch>/:

go-bench  Go benchmarks for each sidecar step in isolation: frame decode, HMAC,
          nonce check, JSON, each pipeline stage, OPA per hook, sanitise, the
          full request handler, payload-size and pattern-count sweeps, and
          inputs that make normalise do the most work.
sidecar   The real sidecar binary under benchmarkv2/overhead/loadgen, with the
          sidecar's per-request timing log on: latency at concurrency 1,
          payload size, throughput by concurrency, and open-loop latency at
          fixed fractions of peak throughput. Every run is a fresh process.
sdk       The Python SDK against the real sidecar: what an agent pays per hook
          call with the semantic scanner off, TF-IDF, and sentence-transformer,
          split into scan, serialise, sign, IPC round trip, and decode.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import itertools
import json
import math
import os
import platform
import re
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
SIDECAR_DIR = REPO_ROOT / "sidecar"
LOADGEN_DIR = HERE / "loadgen"
SDK_ROOT = REPO_ROOT / "sdk" / "python"
if str(SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(SDK_ROOT))

from acf import Firewall  # noqa: E402
from acf.frame import decode_response, encode_request  # noqa: E402
from acf.models import Decision  # noqa: E402

IS_WINDOWS = os.name == "nt"
EXE = ".exe" if IS_WINDOWS else ""
DEFAULT_BIN_DIR = HERE / ".bin"
DEFAULT_RESULTS_DIR = HERE / "results"
CORPUS_PATH = REPO_ROOT / "tests" / "integration" / "adversarial_payloads.json"
SIDECAR_CONFIG = REPO_ROOT / "config" / "sidecar.yaml"
KEY_HEX = "0123456789abcdef" * 4

HOOKS = ("on_prompt", "on_context", "on_tool_call", "on_memory")
# Provenance the SDK's public hook methods set for each hook.
SDK_PROVENANCE = {"on_prompt": "user", "on_context": "rag", "on_tool_call": "agent", "on_memory": "agent"}
SDK_MODES = ("off", "tfidf", "sentence-transformer")
SDK_PHASES = ("scan", "serialise", "sign", "ipc", "decode", "total")
GO_BENCH_PACKAGES = ("./internal/pipeline", "./internal/transport", "./internal/crypto")
SIZES = (256, 1024, 4096, 16384, 65536)
CONCURRENCY = (1, 2, 4, 8, 16, 32, 64)
OPEN_LOOP_LOADS = (0.25, 0.5, 0.75, 0.9)
QUANTILES = {"p50": 0.50, "p90": 0.90, "p95": 0.95, "p99": 0.99, "p999": 0.999}
TIMING_STEPS = (
    "read", "verify", "nonce", "unmarshal", "validate", "normalise", "scan",
    "aggregate", "policy", "sanitise", "log", "write", "total",
)
STAGES = ("validate", "normalise", "scan", "aggregate")


# ── statistics ───────────────────────────────────────────────────────────────


def percentile(ordered: list[float], q: float) -> float | None:
    """Linear-interpolated percentile of an already sorted list."""
    if not ordered:
        return None
    pos = (len(ordered) - 1) * q
    lo, hi = math.floor(pos), math.ceil(pos)
    if lo == hi:
        return float(ordered[lo])
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (pos - lo)


def summarize_ns(values: Iterable[int]) -> dict[str, Any]:
    """Count, mean, percentiles and max of nanosecond samples, in milliseconds."""
    ordered = sorted(values)
    if not ordered:
        return {"count": 0}
    out: dict[str, Any] = {"count": len(ordered), "mean_ms": statistics.fmean(ordered) / 1e6}
    for name, q in QUANTILES.items():
        out[f"{name}_ms"] = percentile(ordered, q) / 1e6
    out["max_ms"] = ordered[-1] / 1e6
    return out


def spread(values: Iterable[float | None]) -> dict[str, float] | None:
    """Median, min and max across repetitions, ignoring missing values."""
    present = [v for v in values if v is not None]
    if not present:
        return None
    return {
        "median": statistics.median(present),
        "min": min(present),
        "max": max(present),
        "n": len(present),
    }


# ── go benchmarks ────────────────────────────────────────────────────────────

BENCH_LINE = re.compile(r"^(Benchmark\S+?)(?:-\d+)?\s+(\d+)\s+([\d.]+) ns/op(.*)$")
BENCH_UNITS = (("mb_per_s", "MB/s"), ("bytes_per_op", "B/op"), ("allocs_per_op", "allocs/op"))


def parse_go_bench(text: str) -> dict[str, dict[str, list[float]]]:
    """Group `go test -bench` result lines by package and benchmark name."""
    package = ""
    results: dict[str, dict[str, list[float]]] = {}
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("pkg: "):
            package = line[len("pkg: "):].rsplit("/", 1)[-1]
            continue
        match = BENCH_LINE.match(line)
        if not match:
            continue
        entry = results.setdefault(
            f"{package}/{match.group(1)}",
            {"ns_per_op": [], **{key: [] for key, _ in BENCH_UNITS}},
        )
        entry["ns_per_op"].append(float(match.group(3)))
        for key, unit in BENCH_UNITS:
            unit_match = re.search(rf"([\d.]+) {re.escape(unit)}", match.group(4))
            if unit_match:
                entry[key].append(float(unit_match.group(1)))
    return results


def summarize_go_bench(parsed: dict[str, dict[str, list[float]]]) -> dict[str, dict[str, Any]]:
    return {
        name: {"runs": len(entry["ns_per_op"]), **{k: spread(v) for k, v in entry.items() if v}}
        for name, entry in parsed.items()
    }


def run_go_bench(args: argparse.Namespace, raw_dir: Path) -> dict[str, Any]:
    stdout_path = raw_dir / "go_bench.txt"
    stderr_path = raw_dir / "go_bench.stderr.txt"
    cmd = [
        "go", "test", "-run", "^$", "-bench", args.bench_filter, "-benchmem",
        "-count", str(args.bench_count), "-benchtime", args.bench_time, *GO_BENCH_PACKAGES,
    ]
    print(f"[go-bench] {' '.join(cmd)}", flush=True)
    started = time.monotonic()
    with stdout_path.open("w", encoding="utf-8") as out, stderr_path.open("w", encoding="utf-8") as err:
        proc = subprocess.run(cmd, cwd=SIDECAR_DIR, stdout=out, stderr=err)
    if proc.returncode != 0:
        raise RuntimeError(f"go test -bench exited {proc.returncode}; see {stdout_path} and {stderr_path}")
    parsed = parse_go_bench(stdout_path.read_text(encoding="utf-8", errors="replace"))
    return {
        "command": " ".join(cmd),
        "count": args.bench_count,
        "benchtime": args.bench_time,
        "elapsed_s": round(time.monotonic() - started, 1),
        "benchmarks": summarize_go_bench(parsed),
    }


# ── sidecar process ──────────────────────────────────────────────────────────

_sidecar_counter = itertools.count()


class Sidecar:
    """One sidecar process on its own IPC address, stopped on exit."""

    def __init__(self, binary: Path, work_dir: Path, name: str, *, timing_log: bool, stderr: str) -> None:
        number = next(_sidecar_counter)
        safe = re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_")
        work_dir.mkdir(parents=True, exist_ok=True)
        self.socket_path = (
            rf"\\.\pipe\acf_overhead_{os.getpid()}_{number}"
            if IS_WINDOWS
            else f"/tmp/acf_overhead_{os.getpid()}_{number}.sock"  # short: sun_path is 104-108 bytes
        )
        self.timing_path = work_dir / f"{safe}.timing.jsonl" if timing_log else None
        self.log_path = work_dir / f"{safe}.sidecar.log" if stderr == "file" else None
        env = {
            **os.environ,
            "ACF_HMAC_KEY": KEY_HEX,
            "ACF_CONFIG": str(SIDECAR_CONFIG),
            "ACF_SOCKET_PATH": self.socket_path,
        }
        env.pop("ACF_TIMING_LOG", None)
        if self.timing_path:
            env["ACF_TIMING_LOG"] = str(self.timing_path)
        self._log = self.log_path.open("wb") if self.log_path else None
        sink: Any = self._log if self._log else subprocess.DEVNULL
        self.process = subprocess.Popen([str(binary)], cwd=REPO_ROOT, env=env, stdout=sink, stderr=sink)
        try:
            self._wait_ready()
        except BaseException:
            self.stop()
            raise

    def __enter__(self) -> Sidecar:
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()

    def log_tail(self, lines: int = 20) -> str:
        if not self.log_path or not self.log_path.exists():
            return "(stderr discarded)"
        text = self.log_path.read_text(encoding="utf-8", errors="replace")
        return "".join(text.splitlines(True)[-lines:])

    def _wait_ready(self, timeout: float = 30.0) -> None:
        """Send one request, the readiness probe, which the timing log records."""
        probe = Firewall(socket_path=self.socket_path, hmac_key=bytes.fromhex(KEY_HEX), enable_semantic_scan=False)
        deadline = time.monotonic() + timeout
        while True:
            if self.process.poll() is not None:
                raise RuntimeError(f"sidecar exited with code {self.process.returncode}:\n{self.log_tail()}")
            try:
                probe.on_prompt("readiness probe")
                return
            except Exception as exc:
                if time.monotonic() > deadline:
                    raise RuntimeError(f"sidecar not ready after {timeout}s: {exc!r}\n{self.log_tail()}") from exc
                time.sleep(0.05)

    def timing_records(self, expected: int, timeout: float = 20.0) -> list[dict[str, Any]]:
        """Complete timing-log lines, once `expected` are written or timeout passes.

        The log is flushed whenever the sidecar's writer drains its queue, so
        the records are on disk shortly after the last response.
        """
        if not self.timing_path:
            return []
        deadline = time.monotonic() + timeout
        while True:
            text = self.timing_path.read_text(encoding="utf-8") if self.timing_path.exists() else ""
            complete = text[: text.rfind("\n") + 1]
            lines = [line for line in complete.splitlines() if line.strip()]
            if len(lines) >= expected or time.monotonic() > deadline:
                return [json.loads(line) for line in lines]
            time.sleep(0.05)

    def stop(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        if self._log and not self._log.closed:
            self._log.close()

    def remove_files(self) -> None:
        for path in (self.timing_path, self.log_path):
            if path and path.exists():
                path.unlink()


def timing_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Per-step summaries of sidecar timing-log records.

    sanitise is summarised over the records that sanitised, since it is zero
    for every other request.
    """
    steps: dict[str, list[int]] = {step: [] for step in TIMING_STEPS}
    for record in records:
        for step in ("read", "verify", "nonce", "unmarshal", "policy", "log", "write", "total"):
            steps[step].append(record[f"{step}_ns"])
        for stage in STAGES:
            if stage in (record.get("stages_ns") or {}):
                steps[stage].append(record["stages_ns"][stage])
        if record.get("sanitise_ns", 0) > 0:
            steps["sanitise"].append(record["sanitise_ns"])
    return {step: summarize_ns(values) for step, values in steps.items()}


# ── sidecar under load ───────────────────────────────────────────────────────


@dataclass(frozen=True)
class LoadCondition:
    name: str
    workload: str
    mode: str = "closed"
    concurrency: int = 1
    requests: int = 20000
    warmup: int = 1000
    rate: float = 0.0
    timing_log: bool = True
    stderr: str = "file"


def load_conditions(quick: bool) -> list[LoadCondition]:
    """Closed-loop conditions, run in every repetition."""
    scale = 10 if quick else 1

    def n(count: int) -> int:
        return max(100, count // scale)

    base = LoadCondition("c1/corpus", "corpus", requests=n(20000), warmup=n(1000))
    conditions = [
        base,
        replace(base, name="c1/corpus/timing-log-off", timing_log=False),
        replace(base, name="c1/corpus/stderr-discarded", stderr="null"),
    ]
    for size in SIZES:
        conditions.append(
            LoadCondition(
                f"c1/context-{size}B", f"context:{size}",
                requests=n(2000 if size >= 65536 else 5000), warmup=n(200),
            )
        )
    for workers in CONCURRENCY[1:]:
        conditions.append(replace(base, name=f"closed/c{workers}/corpus", concurrency=workers))
    return conditions


def open_loop_conditions(peak_rps: float, quick: bool) -> list[LoadCondition]:
    """Fixed-rate conditions at fractions of the peak closed-loop throughput."""
    seconds = 2 if quick else 10
    conditions = []
    for load in OPEN_LOOP_LOADS:
        rate = round(peak_rps * load, 1)
        conditions.append(
            LoadCondition(
                f"open/{int(load * 100)}pct/corpus", "corpus", mode="open",
                requests=max(100, int(rate * seconds)), warmup=200 if quick else 1000, rate=rate,
            )
        )
    return conditions


def run_loadgen(loadgen: Path, socket_path: str, cond: LoadCondition, out_path: Path) -> dict[str, Any]:
    cmd = [
        str(loadgen), "-socket", socket_path, "-key", KEY_HEX, "-workload", cond.workload,
        "-mode", cond.mode, "-concurrency", str(cond.concurrency), "-requests", str(cond.requests),
        "-warmup", str(cond.warmup), "-out", str(out_path),
    ]
    if cond.mode == "open":
        cmd += ["-rate", f"{cond.rate:.3f}"]
    subprocess.run(cmd, check=True, cwd=REPO_ROOT)
    return json.loads(out_path.read_text(encoding="utf-8"))


def run_load_condition(args: argparse.Namespace, bins: dict[str, Path], raw_dir: Path,
                       cond: LoadCondition, rep: int) -> dict[str, Any]:
    tag = f"{cond.name}-rep{rep}"
    print(f"[sidecar] {tag}", flush=True)
    out_path = raw_dir / (re.sub(r"[^A-Za-z0-9]+", "_", tag) + ".loadgen.json")
    with Sidecar(bins["sidecar"], raw_dir, tag, timing_log=cond.timing_log, stderr=cond.stderr) as sidecar:
        data = run_loadgen(bins["loadgen"], sidecar.socket_path, cond, out_path)
        skip = 1 + cond.warmup  # readiness probe, then warmup
        expected = skip + data["completed"]
        records = sidecar.timing_records(expected) if cond.timing_log else []
    if not args.keep_raw:
        sidecar.remove_files()
    measured = records[skip:]
    wall_s = data["wall_ns"] / 1e9
    return {
        "condition": cond.name,
        "repetition": rep,
        "mode": cond.mode,
        "workload": cond.workload,
        "concurrency": cond.concurrency,
        "rate_rps": cond.rate or None,
        "timing_log": cond.timing_log,
        "stderr": cond.stderr,
        "requests": cond.requests,
        "completed": data["completed"],
        "errors": data["errors"],
        "first_error": data.get("first_error"),
        "throughput_rps": data["completed"] / wall_s if wall_s > 0 else None,
        "decisions": data["decisions"],
        "client": summarize_ns(data.get("latencies_ns") or []),
        "send_lag": summarize_ns(data.get("send_lag_ns") or []) if cond.mode == "open" else None,
        "sidecar": timing_summary(measured) if measured else None,
        "timing_records": len(records) if cond.timing_log else None,
        "timing_expected": expected if cond.timing_log else None,
    }


def peak_throughput(runs: list[dict[str, Any]]) -> float:
    closed = [r["throughput_rps"] for r in runs if r["mode"] == "closed" and r["workload"] == "corpus"
              and r["timing_log"] and r["stderr"] == "file" and r["throughput_rps"]]
    if not closed:
        raise RuntimeError("no closed-loop corpus run to size the open-loop rates from")
    return max(closed)


def run_sidecar_part(args: argparse.Namespace, bins: dict[str, Path], raw_dir: Path) -> dict[str, Any]:
    closed = load_conditions(args.quick)
    runs: list[dict[str, Any]] = []
    peak: float | None = None
    open_conditions: list[LoadCondition] = []
    for rep in range(1, args.repetitions + 1):
        # Conditions interleave across repetitions, so slow drift in machine
        # state spreads over all of them instead of biasing one.
        for cond in closed:
            runs.append(run_load_condition(args, bins, raw_dir, cond, rep))
        if peak is None:
            peak = peak_throughput(runs)
            open_conditions = open_loop_conditions(peak, args.quick)
        for cond in open_conditions:
            runs.append(run_load_condition(args, bins, raw_dir, cond, rep))
    return {"peak_rps_first_repetition": peak, "runs": runs}


# ── python sdk ───────────────────────────────────────────────────────────────


def load_corpus() -> list[dict[str, Any]]:
    return json.loads(CORPUS_PATH.read_text(encoding="utf-8"))["payloads"]


def as_text(value: Any) -> str:
    return value if isinstance(value, str) else json.dumps(value, separators=(",", ":"))


def sdk_content(case: dict[str, Any]) -> Any:
    """The content the SDK's public hook method builds for this corpus case."""
    hook, payload = case["hook_type"], case["payload"]
    if hook in ("on_prompt", "on_context"):
        return as_text(payload)
    if hook == "on_tool_call":
        return {"name": payload["name"], "params": payload.get("params", {})}
    if hook == "on_memory":
        return {"key": payload["key"], "value": payload.get("value", ""), "op": payload.get("op", "write")}
    raise ValueError(f"unknown hook {hook!r}")


def public_call(firewall: Any, case: dict[str, Any]) -> Any:
    """Call the SDK's public hook method for this corpus case."""
    hook, content = case["hook_type"], sdk_content(case)
    if hook == "on_prompt":
        return firewall.on_prompt(content)
    if hook == "on_context":
        return firewall.on_context([content])
    if hook == "on_tool_call":
        return firewall.on_tool_call(content["name"], content["params"])
    return firewall.on_memory(content["key"], content["value"], content["op"])


def build_payload_timed(firewall: Firewall, hook: str, content: Any) -> tuple[bytes, int, int]:
    """Firewall._build_payload, with the semantic scan and JSON timed apart.

    Mirrors the SDK method line for line; test_run_overhead checks the bytes
    are identical.
    """
    t0 = time.perf_counter_ns()
    signals = firewall._run_semantic_scanner(hook, content)
    t1 = time.perf_counter_ns()
    ctx = {
        "score": 0.0,
        "signals": signals,
        "provenance": SDK_PROVENANCE[hook],
        "session_id": "",
        "hook_type": hook,
        "payload": content,
        "state": None,
    }
    payload = json.dumps(ctx, separators=(",", ":")).encode("utf-8")
    t2 = time.perf_counter_ns()
    return payload, t1 - t0, t2 - t1


def make_firewall(socket_path: str, mode: str) -> Firewall:
    return Firewall(
        socket_path=socket_path,
        hmac_key=bytes.fromhex(KEY_HEX),
        enable_semantic_scan=mode != "off",
        semantic_backend="tfidf" if mode == "off" else mode,
    )


def run_sdk_mode(args: argparse.Namespace, bins: dict[str, Path], raw_dir: Path,
                 corpus: list[dict[str, Any]], mode: str, rep: int) -> dict[str, Any]:
    requests = args.sdk_st_requests if mode == "sentence-transformer" else args.sdk_requests
    if args.quick:
        requests = max(50, requests // 10)
    warmup = 20 if args.quick else 200
    tag = f"sdk-{mode}-rep{rep}"
    print(f"[sdk] {tag} ({requests} calls per hook, twice)", flush=True)
    by_hook = {hook: [c for c in corpus if c["hook_type"] == hook] for hook in HOOKS}

    with Sidecar(bins["sidecar"], raw_dir, tag, timing_log=True, stderr="file") as sidecar:
        started = time.perf_counter()
        firewall = make_firewall(sidecar.socket_path, mode)
        init_s = time.perf_counter() - started
        for i in range(warmup):
            public_call(firewall, corpus[i % len(corpus)])

        hooks: dict[str, Any] = {}
        raw_path = raw_dir / f"{tag}.jsonl"
        with raw_path.open("w", encoding="utf-8") as raw:
            for hook in HOOKS:
                cases = by_hook[hook]
                api: list[int] = []
                for i in range(requests):
                    t0 = time.perf_counter_ns()
                    public_call(firewall, cases[i % len(cases)])
                    api.append(time.perf_counter_ns() - t0)

                phases: dict[str, list[int]] = {phase: [] for phase in SDK_PHASES}
                key = firewall._transport.key
                for i in range(requests):
                    content = sdk_content(cases[i % len(cases)])
                    t0 = time.perf_counter_ns()
                    payload, scan_ns, serialise_ns = build_payload_timed(firewall, hook, content)
                    t1 = time.perf_counter_ns()
                    frame = encode_request(payload, key)
                    t2 = time.perf_counter_ns()
                    response = firewall._transport._connect_and_send(frame)
                    t3 = time.perf_counter_ns()
                    Decision.from_byte(decode_response(response)["decision"])
                    t4 = time.perf_counter_ns()
                    phases["scan"].append(scan_ns)
                    phases["serialise"].append(serialise_ns)
                    phases["sign"].append(t2 - t1)
                    phases["ipc"].append(t3 - t2)
                    phases["decode"].append(t4 - t3)
                    phases["total"].append(t4 - t0)

                raw.write(json.dumps({"hook": hook, "api_ns": api, **{f"{k}_ns": v for k, v in phases.items()}}) + "\n")
                hooks[hook] = {
                    "api": summarize_ns(api),
                    "phases": {phase: summarize_ns(values) for phase, values in phases.items()},
                }

        skip = 1 + warmup
        expected = skip + 2 * requests * len(HOOKS)
        records = sidecar.timing_records(expected)
    if not args.keep_raw:
        sidecar.remove_files()
    return {
        "mode": mode,
        "repetition": rep,
        "scanner_init_s": init_s,
        "requests_per_hook": requests,
        "hooks": hooks,
        "sidecar": timing_summary(records[skip:]) if len(records) > skip else None,
        "timing_records": len(records),
        "timing_expected": expected,
    }


def run_sdk_part(args: argparse.Namespace, bins: dict[str, Path], raw_dir: Path) -> dict[str, Any]:
    corpus = load_corpus()
    runs = []
    for rep in range(1, args.repetitions + 1):
        for mode in args.sdk_modes:
            runs.append(run_sdk_mode(args, bins, raw_dir, corpus, mode, rep))
    return {"runs": runs}


# ── provenance ───────────────────────────────────────────────────────────────


def sha256_file(path: Path) -> str | None:
    if not path.exists():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def command_output(cmd: list[str], cwd: Path = REPO_ROOT) -> str | None:
    try:
        return subprocess.check_output(cmd, cwd=cwd, text=True, stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def windows_machine_info() -> dict[str, Any]:
    script = (
        "$p = Get-CimInstance Win32_Processor | Select-Object -First 1;"
        "$os = Get-CimInstance Win32_OperatingSystem;"
        "$cs = Get-CimInstance Win32_ComputerSystem;"
        "$b = Get-CimInstance -Namespace root/wmi -ClassName BatteryStatus -ErrorAction SilentlyContinue"
        " | Select-Object -First 1;"
        "[pscustomobject]@{cpu=$p.Name; cores=$p.NumberOfCores; logical=$p.NumberOfLogicalProcessors;"
        " os=$os.Caption; os_build=$os.Version; ram_gb=[math]::Round($cs.TotalPhysicalMemory/1GB,1);"
        " on_ac_power=$(if ($b) { $b.PowerOnline } else { $null })} | ConvertTo-Json -Compress"
    )
    info: dict[str, Any] = {}
    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    # By full path: shells such as Git Bash can start Python without it on PATH.
    powershell = system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    raw = command_output([str(powershell), "-NoProfile", "-NonInteractive", "-Command", script])
    if raw:
        try:
            info.update(json.loads(raw))
        except json.JSONDecodeError:
            pass
    powercfg = system_root / "System32" / "powercfg.exe"
    scheme = command_output([str(powercfg), "/getactivescheme"])
    if scheme:
        match = re.search(r"\(([^)]+)\)\s*$", scheme)
        info["power_plan"] = match.group(1) if match else scheme
    return info


def machine_info() -> dict[str, Any]:
    info: dict[str, Any] = {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "go": command_output(["go", "version"]),
        "logical_cpus": os.cpu_count(),
    }
    if IS_WINDOWS:
        info.update(windows_machine_info())
    else:
        cpuinfo = Path("/proc/cpuinfo")
        if cpuinfo.exists():
            match = re.search(r"^model name\s*:\s*(.+)$", cpuinfo.read_text(), re.MULTILINE)
            info["cpu"] = match.group(1) if match else None
        else:
            info["cpu"] = platform.processor() or None
    return info


def package_versions() -> dict[str, str | None]:
    versions: dict[str, str | None] = {}
    for name in ("numpy", "scikit-learn", "torch", "transformers", "sentence-transformers", "huggingface-hub"):
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            versions[name] = None
    return versions


def scanner_model() -> str | None:
    try:
        from acf.scanners import SemanticScannerConfig
    except ImportError:
        return None
    return SemanticScannerConfig().model_name


def provenance(args: argparse.Namespace, bins: dict[str, Path]) -> dict[str, Any]:
    head = command_output(["git", "rev-parse", "HEAD"])
    dirty = command_output(["git", "status", "--porcelain", "--untracked-files=no"]) if head else None
    policy_dir = REPO_ROOT / "policies" / "v1"
    return {
        "started_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "acf_commit": head,
        "acf_tree_dirty": None if dirty is None else bool(dirty),
        "runner_sha256": sha256_file(Path(__file__).resolve()),
        "loadgen_source_sha256": sha256_file(LOADGEN_DIR / "main.go"),
        "sidecar_binary_sha256": sha256_file(bins["sidecar"]),
        "loadgen_binary_sha256": sha256_file(bins["loadgen"]),
        "sidecar_config_sha256": sha256_file(SIDECAR_CONFIG),
        "policy_config_sha256": sha256_file(policy_dir / "data" / "policy_config.yaml"),
        "jailbreak_patterns_sha256": sha256_file(policy_dir / "data" / "jailbreak_patterns.json"),
        "corpus_sha256": sha256_file(CORPUS_PATH),
        "machine": machine_info(),
        "packages": package_versions(),
        "semantic_model": scanner_model(),
        "clock": "QueryPerformanceCounter (Go internal/clock, Python perf_counter_ns)" if IS_WINDOWS
                 else "CLOCK_MONOTONIC (Go runtime, Python perf_counter_ns)",
        "ipc": "Windows named pipe" if IS_WINDOWS else "Unix domain socket",
        "args": {k: (str(v) if isinstance(v, Path) else v) for k, v in vars(args).items()},
    }


# ── report ───────────────────────────────────────────────────────────────────


def fmt(value: float | None, digits: int = 3) -> str:
    return "n/a" if value is None else f"{value:.{digits}f}"


def fmt_spread(s: dict[str, float] | None, scale: float = 1.0, digits: int = 3) -> str:
    if not s:
        return "n/a"
    if s["n"] == 1:
        return fmt(s["median"] * scale, digits)
    return f"{fmt(s['median'] * scale, digits)} [{fmt(s['min'] * scale, digits)}–{fmt(s['max'] * scale, digits)}]"


def dig(data: Any, *keys: str) -> Any:
    for key in keys:
        if not isinstance(data, dict) or key not in data:
            return None
        data = data[key]
    return data


def across(runs: list[dict[str, Any]], *keys: str) -> dict[str, float] | None:
    return spread(dig(run, *keys) for run in runs)


def render_markdown(summary: dict[str, Any]) -> str:
    prov = summary.get("provenance", {})
    machine = prov.get("machine", {})
    lines = [
        "# ACF runtime overhead",
        "",
        f"ACF commit `{prov.get('acf_commit')}` (tracked changes: {prov.get('acf_tree_dirty')}), "
        f"started {prov.get('started_utc')}.",
        "",
        "| Machine | Value |",
        "|---|---|",
    ]
    for label, key in (("CPU", "cpu"), ("Cores / logical", None), ("RAM GB", "ram_gb"), ("OS", "os"),
                       ("OS build", "os_build"), ("Power plan", "power_plan"), ("On AC power", "on_ac_power"),
                       ("Go", "go"), ("Python", "python")):
        value = f"{machine.get('cores')} / {machine.get('logical') or machine.get('logical_cpus')}" if key is None \
            else machine.get(key)
        lines.append(f"| {label} | {value} |")
    lines += [f"| IPC | {prov.get('ipc')} |", f"| Clock | {prov.get('clock')} |", ""]
    if summary.get("quick"):
        lines += ["**Quick run:** request counts cut tenfold. These numbers are not reportable.", ""]
    lines += [
        "Latencies are median across repetitions, with the [min–max] of the per-repetition value "
        "when there is more than one repetition.",
        "",
    ]

    sdk_runs = dig(summary, "sdk", "runs") or []
    if sdk_runs:
        lines += ["## Python SDK: per hook call", "",
                  "Public hook method, end to end, in ms.", "",
                  "| Scanner | Hook | p50 | p95 | p99 |", "|---|---|---:|---:|---:|"]
        for mode in SDK_MODES:
            runs = [r for r in sdk_runs if r["mode"] == mode]
            if not runs:
                continue
            for hook in HOOKS:
                lines.append(
                    f"| {mode} | {hook} | {fmt_spread(across(runs, 'hooks', hook, 'api', 'p50_ms'))} | "
                    f"{fmt_spread(across(runs, 'hooks', hook, 'api', 'p95_ms'))} | "
                    f"{fmt_spread(across(runs, 'hooks', hook, 'api', 'p99_ms'))} |"
                )
        lines += ["", "Where an SDK call's time goes: p50 per phase in µs, from the step-by-step loop.", "",
                  "| Scanner | Hook | Semantic scan | Serialise | Sign | IPC round trip | Decode | Total | "
                  "Scanner init s |",
                  "|---|---|---:|---:|---:|---:|---:|---:|---:|"]
        for mode in SDK_MODES:
            runs = [r for r in sdk_runs if r["mode"] == mode]
            if not runs:
                continue
            for hook in HOOKS:
                cells = [fmt_spread(across(runs, "hooks", hook, "phases", phase, "p50_ms"), 1000, 1)
                         for phase in SDK_PHASES]
                lines.append(f"| {mode} | {hook} | {' | '.join(cells)} | "
                             f"{fmt_spread(across(runs, 'scanner_init_s'), 1, 2)} |")
        lines.append("")

    load_runs = dig(summary, "sidecar_load", "runs") or []
    if load_runs:
        def runs_for(name: str) -> list[dict[str, Any]]:
            return [r for r in load_runs if r["condition"] == name]

        base = runs_for("c1/corpus")
        if base:
            lines += ["## Sidecar: where a request's time goes", "",
                      "Real sidecar, one client, integration corpus, per-request timing log. µs.", "",
                      "| Step | p50 | p99 | mean | share of mean total |", "|---|---:|---:|---:|---:|"]
            total_mean = across(base, "sidecar", "total", "mean_ms")
            for step in TIMING_STEPS:
                mean = across(base, "sidecar", step, "mean_ms")
                share = (f"{100 * mean['median'] / total_mean['median']:.1f}%"
                         if mean and total_mean and step not in ("total", "sanitise") else "")
                lines.append(
                    f"| {step} | {fmt_spread(across(base, 'sidecar', step, 'p50_ms'), 1000, 1)} | "
                    f"{fmt_spread(across(base, 'sidecar', step, 'p99_ms'), 1000, 1)} | "
                    f"{fmt_spread(mean, 1000, 1)} | {share} |"
                )
            lines += ["", "`read` includes waiting for the client's bytes; `sanitise` is over the requests "
                      "OPA sanitised only.", ""]

        lines += ["## Sidecar: client-observed latency", "",
                  "Go load generator, new connection per request, ms.", "",
                  "| Condition | Reps | p50 | p95 | p99 | Throughput req/s | Errors |",
                  "|---|---:|---:|---:|---:|---:|---:|"]
        seen: list[str] = []
        for run in load_runs:
            if run["condition"] not in seen:
                seen.append(run["condition"])
        for name in seen:
            runs = runs_for(name)
            if runs[0]["mode"] != "closed":
                continue
            lines.append(
                f"| {name} | {len(runs)} | {fmt_spread(across(runs, 'client', 'p50_ms'))} | "
                f"{fmt_spread(across(runs, 'client', 'p95_ms'))} | {fmt_spread(across(runs, 'client', 'p99_ms'))} | "
                f"{fmt_spread(across(runs, 'throughput_rps'), 1, 0)} | {sum(r['errors'] for r in runs)} |"
            )

        size_rows = [name for name in seen if name.startswith("c1/context-")]
        if size_rows:
            lines += ["", "## Payload size", "", "on_context chunk, one client. Client ms, sidecar steps µs (p50).",
                      "", "| Size | Client p50 | Client p99 | Unmarshal | Normalise | Scan | Policy | Sidecar total |",
                      "|---|---:|---:|---:|---:|---:|---:|---:|"]
            for name in size_rows:
                runs = runs_for(name)
                cells = [fmt_spread(across(runs, "sidecar", step, "p50_ms"), 1000, 1)
                         for step in ("unmarshal", "normalise", "scan", "policy", "total")]
                lines.append(f"| {name.removeprefix('c1/context-')} | {fmt_spread(across(runs, 'client', 'p50_ms'))} | "
                             f"{fmt_spread(across(runs, 'client', 'p99_ms'))} | {' | '.join(cells)} |")

        open_rows = [name for name in seen if runs_for(name)[0]["mode"] == "open"]
        if open_rows:
            lines += ["", "## Open loop", "",
                      f"Fixed arrival rate as a fraction of the peak closed-loop throughput "
                      f"({fmt(dig(summary, 'sidecar_load', 'peak_rps_first_repetition'), 0)} req/s in repetition 1). "
                      "Latency from each request's scheduled send time, ms.", "",
                      "| Load | Rate req/s | p50 | p99 | p99.9 | Send lag p99 | Errors |",
                      "|---|---:|---:|---:|---:|---:|---:|"]
            for name in open_rows:
                runs = runs_for(name)
                lines.append(
                    f"| {name.split('/')[1]} | {fmt(runs[0]['rate_rps'], 0)} | "
                    f"{fmt_spread(across(runs, 'client', 'p50_ms'))} | {fmt_spread(across(runs, 'client', 'p99_ms'))} | "
                    f"{fmt_spread(across(runs, 'client', 'p999_ms'))} | "
                    f"{fmt_spread(across(runs, 'send_lag', 'p99_ms'))} | {sum(r['errors'] for r in runs)} |"
                )
        lines.append("")

    bench = dig(summary, "go_bench", "benchmarks") or {}
    if bench:
        lines += ["## Go benchmarks", "",
                  f"`{dig(summary, 'go_bench', 'command')}`. µs/op median [min–max] over runs.", "",
                  "| Benchmark | µs/op | MB/s | B/op | allocs/op |", "|---|---:|---:|---:|---:|"]
        for name, row in bench.items():
            lines.append(
                f"| {name} | {fmt_spread(row.get('ns_per_op'), 1e-3, 2)} | {fmt_spread(row.get('mb_per_s'), 1, 1)} | "
                f"{fmt(dig(row, 'bytes_per_op', 'median'), 0)} | {fmt(dig(row, 'allocs_per_op', 'median'), 0)} |"
            )
        lines.append("")
    return "\n".join(lines)


def write_summary(out_dir: Path, summary: dict[str, Any]) -> None:
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    (out_dir / "summary.md").write_text(render_markdown(summary), encoding="utf-8")


# ── main ─────────────────────────────────────────────────────────────────────


def build_binaries(bin_dir: Path) -> dict[str, Path]:
    bin_dir.mkdir(parents=True, exist_ok=True)
    bins = {"sidecar": bin_dir / f"sidecar{EXE}", "loadgen": bin_dir / f"loadgen{EXE}"}
    subprocess.run(["go", "-C", str(SIDECAR_DIR), "build", "-o", str(bins["sidecar"]), "./cmd/sidecar"], check=True)
    subprocess.run(["go", "-C", str(LOADGEN_DIR), "build", "-o", str(bins["loadgen"]), "."], check=True)
    return bins


def csv_choices(value: str, allowed: tuple[str, ...], label: str) -> list[str]:
    chosen = [item.strip() for item in value.split(",") if item.strip()]
    unknown = sorted(set(chosen) - set(allowed))
    if unknown or not chosen:
        raise argparse.ArgumentTypeError(f"{label} must be a comma list of {', '.join(allowed)}")
    return chosen


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parts = ("go-bench", "sidecar", "sdk")
    parser.add_argument("--parts", default=",".join(parts), type=lambda v: csv_choices(v, parts, "--parts"))
    parser.add_argument("--repetitions", type=int, default=5, help="fresh-process repetitions for sidecar and sdk")
    parser.add_argument("--quick", action="store_true", help="tenfold fewer requests, for checking the harness")
    parser.add_argument("--bench-count", type=int, default=10)
    parser.add_argument("--bench-time", default="1s")
    parser.add_argument("--bench-filter", default=".")
    parser.add_argument("--sdk-modes", default=",".join(SDK_MODES), type=lambda v: csv_choices(v, SDK_MODES, "--sdk-modes"))
    parser.add_argument("--sdk-requests", type=int, default=2000, help="calls per hook, scanner off or TF-IDF")
    parser.add_argument("--sdk-st-requests", type=int, default=500, help="calls per hook, sentence-transformer")
    parser.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS_DIR)
    parser.add_argument("--bin-dir", type=Path, default=DEFAULT_BIN_DIR,
                        help="where binaries are built; keep it out of %%TEMP%% on Windows")
    parser.add_argument("--keep-raw", action="store_true", help="keep sidecar logs and timing logs")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    # The SDK lets these override the constructor; the runner sets scanning per mode.
    for name in ("ACF_SEMANTIC_SCAN", "ACF_SEMANTIC_SCAN_BACKEND", "ACF_SOCKET_PATH", "ACF_HMAC_KEY"):
        os.environ.pop(name, None)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = args.results_dir / f"{stamp}-{platform.system().lower()}-{platform.machine().lower()}"
    raw_dir = out_dir / "raw"
    raw_dir.mkdir(parents=True)

    bins = build_binaries(args.bin_dir)
    summary: dict[str, Any] = {"parts": args.parts, "quick": args.quick, "provenance": provenance(args, bins)}
    write_summary(out_dir, summary)

    if "go-bench" in args.parts:
        summary["go_bench"] = run_go_bench(args, raw_dir)
        write_summary(out_dir, summary)
    if "sidecar" in args.parts:
        summary["sidecar_load"] = run_sidecar_part(args, bins, raw_dir)
        write_summary(out_dir, summary)
    if "sdk" in args.parts:
        summary["sdk"] = run_sdk_part(args, bins, raw_dir)
        write_summary(out_dir, summary)

    summary["finished_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    write_summary(out_dir, summary)
    print(f"results: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
