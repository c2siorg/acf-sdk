# benchmarkv2

Live-agent evaluations for the paper's evaluation section. Each benchmark has
its own subdirectory with a pinned manifest, a runner, tests, and results.

| Directory | Benchmark | What it measures |
|---|---|---|
| [`injecagent/`](injecagent/) | InjecAgent | Attack success rate of a live LLM agent, with and without ACF in the loop |

The v1 runner in `benchmarks/` stays as it is. It replays benchmark text
through ACF hooks with no model, so its numbers are detector catch rates rather
than attack success rates.
