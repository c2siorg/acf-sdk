# Runtime overhead: experimental method

Draft methodology for §eval-overhead (`evaluation.tex`). It is written to be
safe for double-blind review. The harness is in `benchmarkv2/overhead/` (see its
README). The first full run is in
`benchmarkv2/overhead/results/20260914T104233Z-windows-amd64/`.

## How the experiment was run

**Goal.** We measure the latency and throughput that ACF adds to an agent's
execution path. We break that cost down so each part of the enforcement point,
the IPC channel and the decision point can be attributed separately.

**Three levels of measurement.**

1. **Micro-benchmarks.** Go benchmarks time each sidecar step in isolation:
   frame decoding, HMAC verification, the nonce replay check, JSON decoding,
   the four pipeline stages, OPA evaluation for each hook, sanitisation, and
   the complete request handler. Each benchmark runs 10 times for 1 s. We report
   the median, the range, and allocations per operation.
2. **The sidecar under load.** The real sidecar binary is driven by a Go load
   generator that opens one connection per request, as the SDK does. We
   measure latency with a single client, throughput from 1 to 64 concurrent
   clients, and latency at fixed arrival rates of 25–90% of peak throughput.
3. **End to end through the SDK.** The Python SDK's public hook methods call a
   live sidecar with the optional semantic scanner off, on TF-IDF, and on a
   sentence-transformer model. A second loop times the SDK's internal steps
   separately: scanning, serialisation, signing, the IPC round trip and
   decoding.

**Workloads.**

- The 75-case integration corpus, which covers all four hooks and all three
  decisions.
- Synthetic `on_context` chunks from 256 B to 64 KB.
- Inputs chosen to make normalisation do the most work: densely packed base64,
  base64 nested up to 6 layers, URL encoding nested up to 12 layers, and
  zero-width-character padding.
- Synthetic pattern libraries from 79 to 100k patterns.

The shipped configuration and policies are used unchanged.

**Protocol.** Every load condition and every SDK run starts a fresh sidecar
process. A readiness probe and warmup requests are sent first and excluded from
the statistics. Conditions are interleaved across 5 repetitions. We report the
median across repetitions together with the minimum and maximum.

**Environment.** Intel Core Ultra 7 255U (12 cores, 14 threads), 31.5 GB RAM,
Windows 11 Enterprise (build 26100), Windows named pipes, Go 1.26.3, Python
3.14.5, on AC power with the Balanced power plan. Every run records the commit,
file and binary hashes, machine details and package versions.

## Design decisions and why

| Decision | Reason |
|---|---|
| Measure at three levels, not only end to end | An end-to-end number can't show whether cost comes from IPC, policy evaluation, text normalisation or the SDK |
| Time steps inside the real sidecar with an opt-in timing hook, not a copy of the request handler | A copy can drift from the production code. The hook reads no clock unless enabled. It runs only after the response is written, and records go through a buffered queue to a background writer that drops records rather than blocking. A run with the hook off measures its cost |
| Use a high-resolution counter (QueryPerformanceCounter) instead of Go's runtime clock on Windows | Go's clock advanced only in 0.3–0.7 ms steps, and a roughly 10 µs loop measured as zero 997 times out of 1,000. The counter has 100 ns resolution and costs about 60 ns per read |
| One connection per request | This matches the SDK's transport, so client latency includes connection setup as an agent would pay it |
| A fresh process per condition, warmup excluded, repetitions interleaved | This stops caches, the nonce store and JIT-like warm state carrying over between conditions, and spreads slow changes in machine state over all conditions |
| Closed loop for throughput; open loop for latency under load | A closed-loop client slows down when the server does, which hides queueing delay. The open-loop generator measures latency from each request's scheduled send time and reports its own send lag separately |
| Benchmark inputs built to be worst cases, plus a test that each one takes the code path its name claims | Normalisation cost depends on the input, and an attacker controls the input. The test caught generators that silently skipped decoding. One truncated escape sequence disables URL decoding for the whole payload, which is itself a detection gap |
| SDK public methods as the headline figure; internal steps timed in a second loop | The public call is what an agent pays. The second loop reproduces `_build_payload` exactly, and a test checks its output bytes match the SDK's |
| Three scanner modes | The semantic scanner is optional and, when enabled, dominates cost. Reporting it separately keeps the always-on core cost visible |
| Send the sidecar's stderr to a file, and add a run with it discarded | The sidecar writes a log line before every response, so writing to a file reflects a deployment. The discarded run isolates the cost of that line |

## Threats to validity (to disclose)

- **The machine is noisy.** It's a 15 W laptop CPU with mixed core types, on
  the Balanced power plan. Throughput varied by up to 1.5× between repetitions,
  and a CPU-bound benchmark ran about 60% slower late in the run than in an
  earlier smoke test. Effects smaller than about 10 µs, such as the cost of the
  timing hook or the log line, can't be resolved and are reported only as "not
  measurable".
- **Named-pipe contention is a client artifact.** When every pipe instance is
  busy, the Go named-pipe client sleeps a fixed 10 ms before retrying, so tail
  latency at concurrency 2 and above reflects the transport, not the sidecar.
  For the same reason, open-loop results above 25% load aren't reported.
- **Scanner start-up is warm after the first repetition.** Only the first
  repetition measures cold initialisation, because later repetitions reuse the
  same Python process.
- **SDK runs send slightly different payloads.** The public hook methods can't
  send the corpus's `metadata` and `hmac_valid` fields, so those payloads
  differ a little from the sidecar runs.
