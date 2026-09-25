# ACF runtime overhead

ACF commit `7474137baa5c5099740ccc762e1b9fb9c276d794` (tracked changes: True), started 2026-09-14T10:42:48+00:00.

| Machine | Value |
|---|---|
| CPU | Intel(R) Core(TM) Ultra 7 255U |
| Cores / logical | 12 / 14 |
| RAM GB | 31.5 |
| OS | Microsoft Windows 11 Enterprise |
| OS build | 10.0.26100 |
| Power plan | Balanced |
| On AC power | True |
| Go | go version go1.26.3 windows/amd64 |
| Python | 3.14.5 |
| IPC | Windows named pipe |
| Clock | QueryPerformanceCounter (Go internal/clock, Python perf_counter_ns) |

Latencies are median across repetitions, with the [min–max] of the per-repetition value when there is more than one repetition.

## Python SDK: per hook call

Public hook method, end to end, in ms.

| Scanner | Hook | p50 | p95 | p99 |
|---|---|---:|---:|---:|
| off | on_prompt | 0.246 [0.218–0.467] | 0.381 [0.342–0.792] | 0.567 [0.494–1.123] |
| off | on_context | 0.314 [0.285–0.660] | 0.476 [0.441–2.560] | 0.748 [0.685–5.240] |
| off | on_tool_call | 0.290 [0.212–0.449] | 0.443 [0.315–0.625] | 0.641 [0.491–0.799] |
| off | on_memory | 0.305 [0.280–0.427] | 0.434 [0.411–0.627] | 0.637 [0.631–0.832] |
| tfidf | on_prompt | 0.841 [0.751–0.969] | 1.297 [1.292–1.713] | 1.868 [1.772–2.054] |
| tfidf | on_context | 0.929 [0.838–0.983] | 1.507 [1.390–1.905] | 2.137 [1.869–2.308] |
| tfidf | on_tool_call | 0.732 [0.655–1.504] | 1.172 [1.061–2.094] | 1.744 [1.529–2.352] |
| tfidf | on_memory | 0.729 [0.684–1.522] | 1.217 [1.188–2.252] | 1.724 [1.649–2.578] |
| sentence-transformer | on_prompt | 21.143 [17.149–27.325] | 27.777 [21.904–45.330] | 37.489 [31.390–67.387] |
| sentence-transformer | on_context | 22.332 [17.513–29.893] | 32.803 [24.913–43.417] | 37.764 [29.369–51.485] |
| sentence-transformer | on_tool_call | 21.194 [16.481–25.378] | 27.326 [22.098–33.808] | 34.349 [29.787–41.666] |
| sentence-transformer | on_memory | 19.273 [14.464–21.785] | 27.191 [18.531–39.662] | 33.596 [22.272–110.432] |

Where an SDK call's time goes: p50 per phase in µs, from the step-by-step loop.

| Scanner | Hook | Semantic scan | Serialise | Sign | IPC round trip | Decode | Total | Scanner init s |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| off | on_prompt | 0.3 [0.3–0.5] | 10.5 [8.8–17.1] | 12.2 [10.8–19.1] | 215.2 [190.2–381.7] | 5.6 [4.9–9.6] | 244.9 [216.5–429.1] | 0.00 [0.00–0.00] |
| off | on_context | 0.3 [0.3–0.7] | 10.2 [8.7–24.6] | 12.5 [10.6–27.4] | 267.5 [233.7–651.3] | 5.7 [5.0–14.2] | 297.2 [258.2–723.2] | 0.00 [0.00–0.00] |
| off | on_tool_call | 0.4 [0.3–0.4] | 12.9 [10.2–15.1] | 14.2 [11.5–15.8] | 269.1 [192.1–317.6] | 7.0 [5.0–8.1] | 305.9 [218.9–357.4] | 0.00 [0.00–0.00] |
| off | on_memory | 0.3 [0.3–0.4] | 11.5 [11.2–14.8] | 13.6 [11.8–15.6] | 254.2 [236.7–329.4] | 6.3 [5.9–8.1] | 286.8 [268.1–370.1] | 0.00 [0.00–0.00] |
| tfidf | on_prompt | 430.9 [380.0–614.6] | 12.6 [11.1–16.8] | 14.0 [12.8–20.1] | 281.2 [272.0–396.2] | 6.9 [5.9–9.4] | 771.2 [703.6–1063.8] | 0.01 [0.01–14.65] |
| tfidf | on_context | 539.1 [396.8–1379.3] | 15.4 [13.1–37.3] | 17.0 [13.0–48.8] | 392.0 [335.2–1008.4] | 7.6 [5.8–21.8] | 962.2 [774.1–2493.5] | 0.01 [0.01–14.65] |
| tfidf | on_tool_call | 475.0 [358.4–892.7] | 12.3 [9.2–21.1] | 16.5 [11.9–33.1] | 309.1 [238.1–553.2] | 7.5 [5.2–14.4] | 841.0 [624.7–1525.0] | 0.01 [0.01–14.65] |
| tfidf | on_memory | 408.4 [360.4–911.8] | 12.9 [11.6–26.4] | 14.7 [12.7–33.9] | 290.6 [276.6–605.2] | 6.5 [5.8–14.6] | 730.8 [658.1–1591.8] | 0.01 [0.01–14.65] |
| sentence-transformer | on_prompt | 19679.3 [16593.1–27609.7] | 37.3 [31.6–40.1] | 56.3 [49.3–60.0] | 821.1 [731.0–885.4] | 19.7 [16.1–22.9] | 20668.8 [17475.9–28571.9] | 4.41 [4.11–57.37] |
| sentence-transformer | on_context | 21316.0 [16729.2–22835.8] | 37.7 [32.0–38.3] | 56.2 [49.1–59.2] | 992.5 [842.6–1034.3] | 19.8 [16.0–20.5] | 22484.4 [17738.9–24049.5] | 4.41 [4.11–57.37] |
| sentence-transformer | on_tool_call | 19750.5 [15649.3–21087.8] | 36.2 [30.9–37.4] | 54.8 [47.5–57.3] | 770.8 [655.3–804.5] | 18.6 [14.5–19.0] | 20725.0 [16437.4–22050.5] | 4.41 [4.11–57.37] |
| sentence-transformer | on_memory | 16568.8 [13814.5–18511.8] | 35.2 [30.0–37.8] | 52.9 [46.9–56.5] | 794.1 [687.1–839.9] | 16.5 [13.7–17.6] | 17566.0 [14617.4–19587.9] | 4.41 [4.11–57.37] |

## Sidecar: where a request's time goes

Real sidecar, one client, integration corpus, per-request timing log. µs.

| Step | p50 | p99 | mean | share of mean total |
|---|---:|---:|---:|---:|
| read | 8.3 [6.6–9.4] | 69.1 [50.1–79.8] | 13.2 [9.9–14.5] | 5.8% |
| verify | 3.0 [2.3–3.2] | 8.4 [7.1–12.6] | 3.4 [2.7–3.7] | 1.5% |
| nonce | 1.2 [0.9–1.3] | 2.6 [2.1–2.9] | 1.4 [1.2–1.6] | 0.6% |
| unmarshal | 16.9 [13.2–18.5] | 42.1 [32.6–51.3] | 18.4 [14.3–19.9] | 8.0% |
| validate | 0.4 [0.3–0.4] | 0.8 [0.7–1.0] | 0.4 [0.3–0.5] | 0.2% |
| normalise | 8.0 [6.8–8.6] | 28.0 [23.3–32.0] | 8.6 [7.0–9.4] | 3.8% |
| scan | 4.7 [3.7–5.4] | 19.0 [15.4–23.3] | 6.0 [4.8–6.8] | 2.6% |
| aggregate | 0.6 [0.5–0.7] | 1.6 [1.2–1.8] | 0.7 [0.5–0.8] | 0.3% |
| policy | 133.7 [107.2–145.7] | 332.8 [267.7–405.1] | 145.9 [116.6–160.0] | 63.9% |
| sanitise | 2.0 [1.6–2.1] | 5.0 [3.7–5.3] | 2.1 [1.7–2.3] |  |
| log | 17.8 [13.4–19.5] | 53.1 [42.6–67.1] | 19.3 [15.1–21.9] | 8.5% |
| write | 8.6 [6.9–9.3] | 20.4 [14.3–27.3] | 8.8 [6.9–9.9] | 3.9% |
| total | 211.6 [167.4–230.8] | 499.6 [392.7–595.5] | 228.4 [181.3–251.5] |  |

`read` includes waiting for the client's bytes; `sanitise` is over the requests OPA sanitised only.

## Sidecar: client-observed latency

Go load generator, new connection per request, ms.

| Condition | Reps | p50 | p95 | p99 | Throughput req/s | Errors |
|---|---:|---:|---:|---:|---:|---:|
| c1/corpus | 5 | 0.325 [0.240–0.357] | 0.541 [0.402–0.620] | 0.743 [0.578–0.928] | 2866 [2579–3808] | 0 |
| c1/corpus/timing-log-off | 5 | 0.245 [0.222–0.350] | 0.448 [0.378–0.677] | 0.715 [0.569–1.149] | 3579 [2485–4076] | 0 |
| c1/corpus/stderr-discarded | 5 | 0.280 [0.225–0.318] | 0.442 [0.355–0.608] | 0.650 [0.531–0.851] | 3342 [2933–4128] | 0 |
| c1/context-256B | 5 | 0.289 [0.220–0.438] | 0.458 [0.330–0.798] | 0.668 [0.482–1.456] | 3223 [2070–4234] | 0 |
| c1/context-1024B | 5 | 0.355 [0.317–0.395] | 0.537 [0.488–0.605] | 0.790 [0.759–0.888] | 2634 [2407–2905] | 0 |
| c1/context-4096B | 5 | 0.640 [0.564–0.758] | 0.927 [0.785–1.148] | 1.261 [1.142–1.595] | 1520 [1292–1743] | 0 |
| c1/context-16384B | 5 | 2.037 [1.967–2.809] | 2.683 [2.433–5.117] | 3.706 [3.187–6.945] | 503 [323–542] | 0 |
| c1/context-65536B | 5 | 6.143 [5.693–7.860] | 10.385 [7.233–11.573] | 12.297 [8.651–13.507] | 154 [127–172] | 0 |
| closed/c2/corpus | 5 | 0.240 [0.230–0.307] | 0.416 [0.404–0.608] | 10.452 [10.407–10.649] | 4127 [3172–4217] | 0 |
| closed/c4/corpus | 5 | 0.281 [0.254–0.326] | 10.071 [9.845–10.306] | 20.570 [11.107–20.803] | 3877 [3289–4350] | 0 |
| closed/c8/corpus | 5 | 0.316 [0.294–0.339] | 10.617 [10.552–10.688] | 30.814 [30.631–30.961] | 4097 [3873–4438] | 0 |
| closed/c16/corpus | 5 | 0.364 [0.323–0.473] | 20.943 [20.623–30.863] | 51.735 [51.193–72.415] | 4175 [3054–4697] | 0 |
| closed/c32/corpus | 5 | 0.317 [0.311–0.372] | 31.295 [31.120–40.673] | 82.373 [81.234–83.306] | 5532 [4927–5710] | 0 |
| closed/c64/corpus | 5 | 0.387 [0.366–0.484] | 63.338 [61.811–72.864] | 146.173 [143.131–155.069] | 5419 [4762–5693] | 0 |

## Payload size

on_context chunk, one client. Client ms, sidecar steps µs (p50).

| Size | Client p50 | Client p99 | Unmarshal | Normalise | Scan | Policy | Sidecar total |
|---|---:|---:|---:|---:|---:|---:|---:|
| 256B | 0.289 [0.220–0.438] | 0.668 [0.482–1.456] | 16.2 [12.6–23.3] | 25.8 [21.3–30.0] | 5.4 [4.1–8.3] | 106.6 [86.5–152.7] | 193.6 [155.2–273.5] |
| 1024B | 0.355 [0.317–0.395] | 0.790 [0.759–0.888] | 21.6 [19.6–24.3] | 89.6 [86.8–97.4] | 9.8 [8.9–11.2] | 103.7 [95.1–116.3] | 268.5 [248.7–292.4] |
| 4096B | 0.640 [0.564–0.758] | 1.261 [1.142–1.595] | 40.4 [37.0–48.2] | 329.9 [309.7–375.0] | 24.1 [22.1–28.9] | 104.5 [87.6–127.9] | 556.0 [505.2–646.4] |
| 16384B | 2.037 [1.967–2.809] | 3.706 [3.187–6.945] | 121.0 [110.4–158.8] | 1586.2 [1518.5–2012.1] | 71.8 [57.0–110.5] | 99.5 [76.1–202.5] | 1947.0 [1893.8–2614.1] |
| 65536B | 6.143 [5.693–7.860] | 12.297 [8.651–13.507] | 426.4 [409.9–459.3] | 4884.1 [4615.4–6499.2] | 250.9 [234.5–302.6] | 145.1 [118.6–190.2] | 5991.2 [5561.4–7677.2] |

## Open loop

Fixed arrival rate as a fraction of the peak closed-loop throughput (5212 req/s in repetition 1). Latency from each request's scheduled send time, ms.

| Load | Rate req/s | p50 | p99 | p99.9 | Send lag p99 | Errors |
|---|---:|---:|---:|---:|---:|---:|
| 25pct | 1303 | 0.370 [0.308–0.414] | 1.358 [0.744–10.192] | 31.531 [9.821–110.234] | 0.031 [0.019–0.047] | 0 |
| 50pct | 2606 | 0.434 [0.340–0.586] | 189.954 [10.247–548.866] | 380.236 [40.809–957.565] | 0.318 [0.024–6.727] | 766 |
| 75pct | 3909 | 0.590 [0.364–57.911] | 494.990 [21.082–967.262] | 821.231 [72.929–1524.986] | 0.732 [0.029–2.214] | 19280 |
| 90pct | 4691 | 0.445 [0.365–32.714] | 84.288 [30.966–755.185] | 206.636 [71.814–1249.824] | 0.059 [0.027–0.628] | 11391 |

## Go benchmarks

`go test -run ^$ -bench . -benchmem -count 10 -benchtime 1s ./internal/pipeline ./internal/transport ./internal/crypto`. µs/op median [min–max] over runs.

| Benchmark | µs/op | MB/s | B/op | allocs/op |
|---|---:|---:|---:|---:|
| pipeline/BenchmarkStage/validate/corpus | 0.07 [0.06–0.08] | n/a | 128 | 1 |
| pipeline/BenchmarkStage/normalise/corpus | 3.25 [3.07–3.48] | n/a | 400 | 7 |
| pipeline/BenchmarkStage/scan/corpus | 0.64 [0.61–0.66] | n/a | 218 | 3 |
| pipeline/BenchmarkStage/aggregate/corpus | 0.09 [0.09–0.10] | n/a | 128 | 1 |
| pipeline/BenchmarkPolicy/on_prompt | 47.99 [47.58–49.78] | n/a | 21463 | 519 |
| pipeline/BenchmarkPolicy/on_context | 72.98 [69.50–75.19] | n/a | 30092 | 743 |
| pipeline/BenchmarkPolicy/on_tool_call | 64.69 [53.57–104.34] | n/a | 22793 | 532 |
| pipeline/BenchmarkPolicy/on_memory | 64.10 [61.15–84.34] | n/a | 26044 | 590 |
| pipeline/BenchmarkPipeline/corpus | 75.02 [71.13–117.65] | n/a | 25294 | 583 |
| pipeline/BenchmarkPipeline/on_prompt | 60.27 [58.07–65.71] | n/a | 22508 | 529 |
| pipeline/BenchmarkPipeline/on_context | 90.40 [85.21–112.80] | n/a | 31563 | 756 |
| pipeline/BenchmarkPipeline/on_tool_call | 56.42 [50.73–71.91] | n/a | 23315 | 540 |
| pipeline/BenchmarkPipeline/on_memory | 61.92 [58.72–77.39] | n/a | 27424 | 604 |
| pipeline/BenchmarkSize/normalise/benign/size=256 | 12.08 [11.40–12.71] | 21.2 [20.1–22.5] | 1234 | 7 |
| pipeline/BenchmarkSize/normalise/benign/size=1024 | 49.81 [46.98–59.73] | 20.6 [17.1–21.8] | 5660 | 8 |
| pipeline/BenchmarkSize/normalise/benign/size=4096 | 271.35 [219.67–315.58] | 15.1 [13.0–18.6] | 22466 | 8 |
| pipeline/BenchmarkSize/normalise/benign/size=16384 | 1460.93 [1123.68–1812.27] | 11.2 [9.0–14.6] | 88239 | 8 |
| pipeline/BenchmarkSize/normalise/benign/size=65536 | 6323.12 [4390.09–8647.29] | 10.4 [7.6–14.9] | 352584 | 8 |
| pipeline/BenchmarkSize/normalise/injected/size=256 | 16.19 [12.87–21.32] | 15.8 [12.0–19.9] | 1234 | 7 |
| pipeline/BenchmarkSize/normalise/injected/size=1024 | 66.35 [55.97–71.51] | 15.4 [14.3–18.3] | 5657 | 8 |
| pipeline/BenchmarkSize/normalise/injected/size=4096 | 237.05 [195.01–258.75] | 17.3 [15.8–21.0] | 22458 | 8 |
| pipeline/BenchmarkSize/normalise/injected/size=16384 | 1249.99 [998.21–1319.35] | 13.1 [12.4–16.4] | 88241 | 8 |
| pipeline/BenchmarkSize/normalise/injected/size=65536 | 5051.71 [4164.00–5553.05] | 13.0 [11.8–15.7] | 352562 | 8 |
| pipeline/BenchmarkSize/scan/benign/size=256 | 1.04 [0.95–1.13] | 247.1 [226.2–268.4] | 386 | 2 |
| pipeline/BenchmarkSize/scan/benign/size=1024 | 4.19 [3.66–4.70] | 244.5 [218.0–279.9] | 1157 | 2 |
| pipeline/BenchmarkSize/scan/benign/size=4096 | 15.30 [13.02–16.86] | 267.8 [242.9–314.5] | 4242 | 2 |
| pipeline/BenchmarkSize/scan/benign/size=16384 | 62.21 [51.42–69.94] | 263.4 [234.3–318.6] | 16573 | 2 |
| pipeline/BenchmarkSize/scan/benign/size=65536 | 259.27 [227.84–277.89] | 252.8 [235.8–287.6] | 65850 | 2 |
| pipeline/BenchmarkSize/scan/injected/size=256 | 1.37 [1.24–1.62] | 187.2 [157.7–207.2] | 563 | 6 |
| pipeline/BenchmarkSize/scan/injected/size=1024 | 4.69 [3.76–5.09] | 218.3 [201.2–272.0] | 1334 | 6 |
| pipeline/BenchmarkSize/scan/injected/size=4096 | 16.16 [13.55–17.63] | 253.5 [232.4–302.2] | 4418 | 6 |
| pipeline/BenchmarkSize/scan/injected/size=16384 | 57.13 [52.47–68.20] | 286.8 [240.2–312.3] | 16748 | 6 |
| pipeline/BenchmarkSize/scan/injected/size=65536 | 202.17 [196.25–234.84] | 324.2 [279.1–333.9] | 66010 | 6 |
| pipeline/BenchmarkSize/pipeline/benign/size=256 | 62.38 [58.66–76.79] | 4.1 [3.3–4.4] | 25120 | 538 |
| pipeline/BenchmarkSize/pipeline/benign/size=1024 | 106.79 [100.74–119.25] | 9.6 [8.6–10.2] | 30319 | 539 |
| pipeline/BenchmarkSize/pipeline/benign/size=4096 | 370.14 [255.16–488.37] | 11.1 [8.4–16.1] | 50466 | 539 |
| pipeline/BenchmarkSize/pipeline/benign/size=16384 | 1164.46 [1095.32–1364.49] | 14.1 [12.0–15.0] | 128670 | 539 |
| pipeline/BenchmarkSize/pipeline/benign/size=65536 | 4248.72 [4059.20–5990.49] | 15.4 [10.9–16.1] | 444408 | 541 |
| pipeline/BenchmarkSize/pipeline/injected/size=256 | 81.99 [80.20–125.69] | 3.1 [2.0–3.2] | 35982 | 861 |
| pipeline/BenchmarkSize/pipeline/injected/size=1024 | 148.81 [136.04–225.64] | 6.9 [4.5–7.5] | 41196 | 860 |
| pipeline/BenchmarkSize/pipeline/injected/size=4096 | 296.34 [271.53–327.99] | 13.8 [12.5–15.1] | 61273 | 860 |
| pipeline/BenchmarkSize/pipeline/injected/size=16384 | 1162.88 [1117.12–1458.12] | 14.1 [11.2–14.7] | 139468 | 860 |
| pipeline/BenchmarkSize/pipeline/injected/size=65536 | 5401.51 [4990.67–6326.19] | 12.1 [10.4–13.1] | 454360 | 862 |
| pipeline/BenchmarkNormaliseAdversarial/benign/size=4096 | 229.13 [196.78–254.93] | 17.9 [16.1–20.8] | 22410 | 8 |
| pipeline/BenchmarkNormaliseAdversarial/benign/size=65536 | 4639.11 [3988.91–5236.70] | 14.1 [12.5–16.4] | 353060 | 10 |
| pipeline/BenchmarkNormaliseAdversarial/base64-tokens/size=4096 | 228.34 [205.79–273.59] | 18.0 [15.0–19.9] | 49550 | 276 |
| pipeline/BenchmarkNormaliseAdversarial/base64-tokens/size=65536 | 8834.63 [8068.78–9285.80] | 7.4 [7.1–8.1] | 850543 | 4129 |
| pipeline/BenchmarkNormaliseAdversarial/base64-depth=1/size=4096 | 163.91 [152.39–287.13] | 25.0 [14.3–26.9] | 19361 | 9 |
| pipeline/BenchmarkNormaliseAdversarial/base64-depth=1/size=65536 | 3444.42 [2842.89–5002.59] | 19.0 [13.1–23.1] | 320142 | 10 |
| pipeline/BenchmarkNormaliseAdversarial/base64-depth=3/size=4096 | 114.25 [106.04–124.30] | 35.8 [33.0–38.6] | 22395 | 13 |
| pipeline/BenchmarkNormaliseAdversarial/base64-depth=3/size=65536 | 2335.61 [2002.27–2479.49] | 28.1 [26.4–32.7] | 360982 | 15 |
| pipeline/BenchmarkNormaliseAdversarial/base64-depth=6/size=4096 | 76.01 [67.62–83.22] | 53.9 [49.2–60.6] | 24358 | 19 |
| pipeline/BenchmarkNormaliseAdversarial/base64-depth=6/size=65536 | 1455.77 [1292.81–1666.63] | 45.0 [39.3–50.7] | 392336 | 21 |
| pipeline/BenchmarkNormaliseAdversarial/url-depth=4/size=4096 | 278.20 [232.14–449.13] | 14.7 [9.1–17.6] | 26938 | 11 |
| pipeline/BenchmarkNormaliseAdversarial/url-depth=4/size=65536 | 5792.54 [5308.75–10447.15] | 11.3 [6.3–12.3] | 443480 | 15 |
| pipeline/BenchmarkNormaliseAdversarial/url-depth=12/size=4096 | 228.94 [213.23–287.15] | 17.9 [14.3–19.2] | 41875 | 19 |
| pipeline/BenchmarkNormaliseAdversarial/url-depth=12/size=65536 | 4417.68 [4023.27–5847.24] | 14.8 [11.2–16.3] | 672180 | 27 |
| pipeline/BenchmarkNormaliseAdversarial/zerowidth/size=4096 | 122.28 [100.29–202.96] | 33.5 [20.2–40.8] | 23738 | 9 |
| pipeline/BenchmarkNormaliseAdversarial/zerowidth/size=65536 | 2283.70 [1925.83–3356.66] | 28.7 [19.5–34.0] | 371616 | 10 |
| pipeline/BenchmarkScanPatterns/patterns=79/size=4096 | 18.00 [16.97–22.85] | 227.6 [179.3–241.4] | 4296 | 6 |
| pipeline/BenchmarkScanPatterns/patterns=1000/size=4096 | 18.68 [15.85–21.17] | 219.2 [193.5–258.5] | 4130 | 2 |
| pipeline/BenchmarkScanPatterns/patterns=10000/size=4096 | 22.08 [16.01–23.81] | 185.5 [172.0–255.9] | 4272 | 2 |
| pipeline/BenchmarkScanPatterns/patterns=100000/size=4096 | 19.07 [16.46–28.19] | 214.8 [145.3–248.8] | 5072 | 2 |
| pipeline/BenchmarkSanitise/size=1024 | 0.12 [0.10–0.14] | 8700.0 [7301.2–10503.6] | 32 | 2 |
| pipeline/BenchmarkSanitise/size=16384 | 0.13 [0.10–0.18] | 129708.9 [90085.9–168248.8] | 32 | 2 |
| transport/BenchmarkDecodeRequest/size=256 | 0.22 [0.20–0.29] | 1926.1 [1464.9–2080.2] | 528 | 3 |
| transport/BenchmarkDecodeRequest/size=1024 | 0.46 [0.43–0.51] | 2578.0 [2312.1–2749.1] | 1296 | 3 |
| transport/BenchmarkDecodeRequest/size=4096 | 1.45 [1.23–1.68] | 2948.7 [2533.6–3453.9] | 5008 | 3 |
| transport/BenchmarkDecodeRequest/size=16384 | 4.79 [4.29–11.88] | 3457.7 [1392.8–3852.9] | 18576 | 3 |
| transport/BenchmarkDecodeRequest/size=65536 | 17.25 [15.61–21.93] | 3810.0 [2995.5–4209.9] | 73872 | 3 |
| transport/BenchmarkVerify/size=256 | 1.51 [0.81–2.42] | 242.4 [151.2–454.5] | 928 | 7 |
| transport/BenchmarkVerify/size=1024 | 1.66 [1.51–1.86] | 684.2 [609.6–751.9] | 1792 | 7 |
| transport/BenchmarkVerify/size=4096 | 4.11 [3.77–6.40] | 1022.9 [656.9–1116.1] | 5376 | 7 |
| transport/BenchmarkVerify/size=16384 | 18.89 [15.55–21.63] | 873.8 [762.6–1060.5] | 18944 | 7 |
| transport/BenchmarkVerify/size=65536 | 108.13 [66.96–132.06] | 607.3 [497.1–980.4] | 74240 | 7 |
| transport/BenchmarkUnmarshal/corpus | 5.21 [4.87–6.34] | n/a | 876 | 17 |
| transport/BenchmarkUnmarshal/size=256 | 6.47 [4.47–7.19] | 56.5 [50.9–81.8] | 680 | 11 |
| transport/BenchmarkUnmarshal/size=1024 | 14.23 [7.92–17.87] | 79.7 [63.5–143.2] | 1448 | 11 |
| transport/BenchmarkUnmarshal/size=4096 | 21.43 [20.38–27.90] | 196.3 [150.8–206.4] | 4520 | 11 |
| transport/BenchmarkUnmarshal/size=16384 | 78.28 [72.57–115.42] | 210.7 [142.9–227.3] | 16808 | 11 |
| transport/BenchmarkUnmarshal/size=65536 | 357.79 [312.58–516.41] | 183.6 [127.1–210.0] | 65960 | 11 |
| transport/BenchmarkHandleConn/corpus/log=discard | 127.59 [92.92–167.43] | n/a | 29196 | 630 |
| transport/BenchmarkHandleConn/corpus/log=file | 129.88 [108.75–260.69] | n/a | 29366 | 634 |
| transport/BenchmarkHandleConn/corpus/log=discard/timing=on | 99.15 [91.12–140.03] | n/a | 29592 | 671 |
| transport/BenchmarkHandleConn/size=256/log=discard | 129.50 [96.28–165.44] | n/a | 29226 | 577 |
| transport/BenchmarkHandleConn/size=1024/log=discard | 279.31 [179.38–631.74] | n/a | 36910 | 578 |
| transport/BenchmarkHandleConn/size=4096/log=discard | 2157.03 [1429.36–4578.62] | n/a | 67638 | 578 |
| transport/BenchmarkHandleConn/size=16384/log=discard | 1991.60 [1595.49–3938.86] | n/a | 185631 | 580 |
| transport/BenchmarkHandleConn/size=65536/log=discard | 6630.63 [6089.05–9748.80] | n/a | 660046 | 581 |
| transport/BenchmarkIPCRoundTrip/auth-only/corpus | 143.74 [110.21–228.84] | n/a | 3956 | 48 |
| transport/BenchmarkIPCRoundTrip/full/corpus | 289.40 [270.66–379.12] | n/a | 30906 | 651 |
| crypto/BenchmarkNonceStoreSeen/stored=0 | 0.46 [0.40–0.64] | n/a | 164 | 1 |
| crypto/BenchmarkNonceStoreSeen/stored=100000 | 0.47 [0.43–0.88] | n/a | 166 | 1 |
