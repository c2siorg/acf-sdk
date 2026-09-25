# Runtime overhead

This runner measures what ACF adds to an agent's execution path, from single
sidecar steps up to a Python SDK hook call. It backs §eval-overhead in the paper.

## What it measures

| Part | Workload | Numbers |
|---|---|---|
| `go-bench` | Go benchmarks for each sidecar step, run in isolation | ns/op, B/op and allocs/op for frame decode, HMAC check, nonce check, JSON decoding, each pipeline stage, OPA evaluation per hook, sanitise, and the full request handler. Also sweeps payload size (256 B to 64 KB), pattern-library size (79 to 100k patterns), and inputs chosen to make normalise do the most work |
| `sidecar` | The real sidecar binary driven by [`loadgen/`](loadgen/) | Client latency percentiles and throughput, plus the sidecar's own time for each step from its timing log |
| `sdk` | The Python SDK calling the real sidecar | Per-call latency for each hook, with the semantic scanner off, on TF-IDF, and on the sentence-transformer model. Each call is split into scan, serialisation, signing, IPC round trip, and decoding |

All requests come from the integration corpus
(`tests/integration/adversarial_payloads.json`, 75 cases over 4 hooks) or from
the `on_context` chunks generated in `sidecar/internal/benchdata`.

## Protocol

- **Timing inside the sidecar.** Set `ACF_TIMING_LOG` to a file path to turn on
  the timing log. The sidecar then writes one JSON line per request with the
  time taken by each step. The timing callback runs after the response is
  written. Records go through a buffered channel to a background writer, and a
  full buffer drops records instead of blocking the request. With the variable
  unset, no clock is read. The `c1/corpus/timing-log-off` condition measures
  the cost of turning it on.
- **Clock.** On Windows, Go's runtime clock only advances every 0.3 to 0.7 ms.
  That's too coarse for these steps: a 10 µs loop read as zero in 997 out of
  1,000 tries. So the sidecar timing log and the load generator read time
  through `sidecar/internal/clock`, which uses QueryPerformanceCounter on
  Windows (100 ns resolution, about 60 ns per call). Python's `perf_counter_ns`
  already uses the same counter.
- **Fresh processes.** Every load condition and every SDK run starts its own
  sidecar and sends a readiness probe, then warmup requests. Probe and warmup
  requests are excluded from all statistics.
- **Repetitions.** Conditions alternate across repetitions (default 5), so
  gradual changes in machine state affect all of them rather than skewing one.
  Reports show the median across repetitions, with the minimum and maximum.
- **Connections.** Each request opens a new connection, as the Python SDK
  transport does.
- **Closed loop.** At concurrency *c*, *c* workers send requests one after
  another until the request count is reached. This measures throughput at that
  concurrency.
- **Open loop.** Requests are sent on a fixed schedule at 25, 50, 75 and 90 %
  of the peak closed-loop throughput from repetition 1. Latency is measured from
  each request's scheduled send time, so queueing behind a slow request is
  counted rather than hidden. The time the load generator itself starts late is
  reported separately as send lag.
- **Concurrency on Windows.** When every named-pipe instance is busy, go-winio's
  `DialPipe` sleeps a fixed 10 ms and tries again (`pipe.go`, v0.6.2) instead
  of calling WaitNamedPipe. At concurrency 2 and above, closed-loop and
  open-loop tail latency therefore rises in 10 ms steps, while p50 barely
  changes. Those steps come from the client's dial, not from sidecar work, and
  the sidecar timing log doesn't include them. The Python SDK handles a busy
  pipe (error 231) worse: it treats it as a refused connection, waits 100 ms
  and then 200 ms, and gives up after three tries. So read concurrency results
  on Windows as a property of the named-pipe transport. The concurrency 1
  results are the per-call overhead.
- **Logging.** The shipped sidecar writes one log line per request before
  responding, and `log_level` in `sidecar.yaml` doesn't change that. Runs send
  the sidecar's stderr to a file. `c1/corpus/stderr-discarded` measures the cost
  of that log line, and the Go benchmark `BenchmarkHandleConn/corpus/log=*`
  measures it without IPC.
- **SDK phases.** The public-method loop is the headline number. The phase
  loop repeats the SDK's internal steps (`_run_semantic_scanner`, then JSON
  serialisation, `encode_request`, `Transport._connect_and_send`, and
  `decode_response`) so each step can be timed.
  `test_run_overhead.py` checks that its payload bytes match
  `Firewall._build_payload`. The public methods can't send the corpus's
  `metadata` (on tool calls) or `hmac_valid` (on memory reads), so SDK runs
  leave those fields out.

## Running

Requires Go and Python 3.10+. The `sdk` part's TF-IDF and sentence-transformer
modes also need the SDK's `[scanners]` extra. On first use, the
sentence-transformer mode downloads `paraphrase-multilingual-MiniLM-L12-v2`
from Hugging Face.

On Windows, keep the binaries out of `%TEMP%`: the virus scanner blocks newly
built binaries there, and the default `.bin/` avoids it. Close other heavy
programs first, and note the power plan, which the run records.

```sh
# Check the harness: one repetition, a tenth of the requests, a few minutes.
python benchmarkv2/overhead/run_overhead.py --quick --repetitions 1 --bench-count 1 --bench-time 100ms

# Full run.
python benchmarkv2/overhead/run_overhead.py

# One part at a time.
python benchmarkv2/overhead/run_overhead.py --parts go-bench
python benchmarkv2/overhead/run_overhead.py --parts sidecar --repetitions 5
python benchmarkv2/overhead/run_overhead.py --parts sdk --sdk-modes off,tfidf

# The Go benchmarks directly.
cd sidecar && go test -run '^$' -bench . -benchmem ./internal/pipeline ./internal/transport ./internal/crypto
```

## Outputs

`results/<UTC timestamp>-<os>-<arch>/`:

- `summary.md`: result tables for the SDK, sidecar steps, client latency,
  payload size, open loop, and Go benchmarks.
- `summary.json`: every run's statistics, plus provenance. That covers the
  commit, file and binary hashes, machine (CPU, RAM, OS build, power plan, AC
  power), Go and Python versions, scanner package versions, clock source, and
  arguments.
- `raw/` (not committed):
  - `go_bench.txt`
  - one `*.loadgen.json` per run, holding every request latency
  - one `sdk-*.jsonl` per SDK run, holding every call's phase timings
  - sidecar logs and timing logs, kept only with `--keep-raw`

The summary files are rewritten after each part, so a stopped run still leaves
the finished parts.

## Tests

```sh
python -m pytest benchmarkv2/overhead
cd sidecar && go test ./internal/benchdata ./internal/clock ./internal/telemetry ./internal/pipeline ./internal/transport
```

`TestBenchWorkloads_ExerciseTheirPaths` checks that each benchmark input takes
the code path its name describes. The injected chunk must be flagged, the clean
chunk allowed, and the nested encodings decoded.
