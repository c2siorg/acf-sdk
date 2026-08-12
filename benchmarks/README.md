# External benchmark runner

This runner replays public benchmark payloads through the Python ACF hook and a live Go sidecar. It does not run an agent model, so the reported number is detector catch rate, not agent attack success rate

InjecAgent tool responses map to `on_context`. ACF v1 has no `on_tool_result` hook, so the result is labeled as a proxy. `SANITISE` and `BLOCK` both count as caught because both stop the original injected response from reaching the model unchanged

The datasets and licenses are fetched at the commits and hashes in `manifest.json`. They are cached outside the repo and are not vendored here

Set up the Python dependencies:

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e 'sdk/python[scanners,dev]' PyYAML
```

Run the lexical path:

```sh
python3 benchmarks/run_benchmark.py --scanner off
```

Run the current TF-IDF semantic path on top of the same sidecar:

```sh
python3 benchmarks/run_benchmark.py --scanner on --semantic-backend tfidf
```

Run the public 8-case PINT format smoke test:

```sh
python3 benchmarks/run_benchmark.py --benchmark pint-format --scanner off
```

The PINT command needs PyYAML. The public file explicitly says it is only a format example, not the 4314-case PINT benchmark. Its attack detection and benign false-positive rates are reported separately

Each run first checks a lexical attack, a benign context, and a semantic-only attack against the same live process. These 3 warmup calls are excluded from latency. The result file has those controls plus a per-case verdict, latency, SDK semantic signals, source index, content hash, and exact-overlap status. The full result and the exact-overlap-excluded result are both included. InjecAgent also reports its 510 direct-harm and 544 data-stealing cases separately

Each JSON result has an outcome hash over case IDs, verdicts, semantic signals, and overlap reasons. Latency is excluded from that hash, so repeated runs can check decision reproducibility. The runner and manifest hashes are recorded too. A compact Markdown summary is written next to each full JSON. Once all 6 OFF, TF-IDF, and MiniLM runs from the current runner exist, `evaluation_summary.md` is updated with the paper table

Latency is measured with 1 sequential hook call per case after the 3 preflight calls. Package versions, platform, Python, and Go versions are recorded in the JSON output

For a quick local check:

```sh
python3 benchmarks/run_benchmark.py --scanner off --limit 10
python3 -m pytest benchmarks/test_run_benchmark.py
```

Limited and split runs get separate output filenames and never update `evaluation_summary.md`
