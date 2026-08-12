# External benchmark evaluation

ACF commit: `8811fad3a11b934cc5cd429e78176b11f81a196d`

These are detector catch rates through live ACF hooks and the Go sidecar. They are not agent attack success rates

| Dataset | Scanner | Attack detection | Overlap-excluded detection | Benign false positives | SDK signaled | Verdict lift vs OFF | P50 ms | P90 ms | P95 ms | P99 ms |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| InjecAgent base | OFF | 0/1054 (0.00%) | 0/1054 (0.00%) | n/a | 0/1054 | baseline | 1.1176 | 2.4797 | 3.4515 | 5.8456 |
| InjecAgent base | TF-IDF ON | 0/1054 (0.00%) | 0/1054 (0.00%) | n/a | 19/1054 | +0 non-ALLOW, +0 ALLOW | 4.6853 | 7.9590 | 9.4558 | 12.1904 |
| InjecAgent base | MiniLM ON | 0/1054 (0.00%) | 0/1054 (0.00%) | n/a | 15/1054 | +0 non-ALLOW, +0 ALLOW | 73.4042 | 211.3377 | 260.7931 | 504.7795 |
| PINT format smoke test | OFF | 1/2 (50.00%) | 0/1 (0.00%) | 0/6 (0.00%) | 0/8 | baseline | 0.9158 | 2.3014 | 2.5196 | 2.6942 |
| PINT format smoke test | TF-IDF ON | 1/2 (50.00%) | 0/1 (0.00%) | 0/6 (0.00%) | 1/8 | +0 non-ALLOW, +0 ALLOW | 7.0787 | 12.3188 | 13.2252 | 13.9502 |
| PINT format smoke test | MiniLM ON | 1/2 (50.00%) | 0/1 (0.00%) | 0/6 (0.00%) | 1/8 | +0 non-ALLOW, +0 ALLOW | 141.3208 | 162.1212 | 163.9313 | 165.3794 |

## InjecAgent split results

| Scanner | Direct harm caught | Direct harm SDK signaled | Data stealing caught | Data stealing SDK signaled |
| --- | ---: | ---: | ---: | ---: |
| OFF | 0/510 | 0/510 | 0/544 | 0/544 |
| TF-IDF ON | 0/510 | 19/510 | 0/544 | 0/544 |
| MiniLM ON | 0/510 | 15/510 | 0/544 | 0/544 |

## Interpretation

InjecAgent maps injected tool responses to `on_context` because ACF v1 has no `on_tool_result` hook. All 1054 cases are attacks, so InjecAgent does not provide a false-positive rate

For InjecAgent, TF-IDF emitted SDK signals on 19/1054 cases and MiniLM emitted SDK signals on 15/1054 cases. Across both ON runs, 0 final verdicts changed. The signaled categories with no sidecar weight or direct rule in `context.rego` were `encoding_evasion`, `role_hijack`, `tool_abuse`

For the PINT format sample, TF-IDF emitted SDK signals on 1/8 cases and MiniLM emitted SDK signals on 1/8 cases. Across both ON runs, 0 final verdicts changed. The signaled categories with no sidecar weight or direct rule in `prompt.rego` were `tool_abuse`

The public PINT file is a format sample, not the full benchmark. OFF caught 1/2 attacks, and 1 caught attack had an exact pattern overlap. After excluding exact overlaps, it caught 0/1 attacks with 0/6 benign false positives

All latency values are local descriptive measurements. Raw timing files are not committed, so rerun the pinned commands to reproduce them on another machine

PINT latency percentiles are descriptive only because the public sample has 8 cases

## Run provenance

| Runtime field | Value |
| --- | --- |
| Platform | `macOS-26.5.2-arm64-arm-64bit-Mach-O` |
| Python | `3.14.2` |
| Go | `go version go1.25.6 darwin/arm64` |
| Concurrency | `1` sequential call per case |
| Runner commit | `bf41a12bc17f6c0b78f1dca42b8fdec22a0741e0` |
| Runner SHA256 | `d3dc229952a203e657782d7637cc82306287121d0e4532a368556254ac050dd9` |
| Manifest SHA256 | `f20e0712e1e7234286b4d3bae6c4e8e91dd4920dc01b3374faedcd8707722bcb` |

| Scanner | Model | Model snapshot | Package versions |
| --- | --- | --- | --- |
| TF-IDF | tfidf-svd | `n/a` | numpy 2.3.5, pydantic 2.13.2, scikit-learn 1.8.0 |
| MiniLM | all-MiniLM-L6-v2 | `1110a243fdf4706b3f48f1d95db1a4f5529b4d41` | huggingface-hub 1.8.0, numpy 2.3.5, pydantic 2.13.2, sentence-transformers 5.3.0, torch 2.12.0, transformers 5.4.0 |

| Dataset | Scanner | Outcome SHA256 |
| --- | --- | --- |
| InjecAgent base | OFF | `4fe3b1e323b3a91cd72e735c79048963466ed5f7c814c5957302e3aff1c86954` |
| InjecAgent base | TF-IDF ON | `acd56a71714038701e6170aea30fcd2af8d4693d275f30c5a97c99bfac5aa735` |
| InjecAgent base | MiniLM ON | `618c25c620fc35f95d625e7e4d0e415dd604a1738cc1a7cf3f01ff740986e6b9` |
| PINT format smoke test | OFF | `5050e5eca933eec08851f85c3459e6bd03e315f534b1b8d2d39739a4d21f9d83` |
| PINT format smoke test | TF-IDF ON | `a2c87ac2445e691e84494f43f1446d49822d9af954dbc2f20ffcebc17c485011` |
| PINT format smoke test | MiniLM ON | `e35f3ae760d87016e8ebf159ee832d17a6d2be0bce113783bc5d77a4fc04ec6e` |
