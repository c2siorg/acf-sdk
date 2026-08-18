# External benchmark evaluation

ACF commit: `8811fad3a11b934cc5cd429e78176b11f81a196d`

These are detector catch rates through live ACF hooks and the Go sidecar. They are not agent attack success rates

| Dataset | Scanner | Attack detection | Overlap-excluded detection | Benign false positives | SDK signaled | Verdict lift vs OFF | P50 ms | P90 ms | P95 ms | P99 ms |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| InjecAgent base | OFF | 0/1054 (0.00%) | 0/1054 (0.00%) | n/a | 0/1054 | baseline | 0.1610 | 0.1836 | 0.1944 | 0.2630 |
| InjecAgent base | TF-IDF ON | 0/1054 (0.00%) | 0/1054 (0.00%) | n/a | 19/1054 | +0 non-ALLOW, +0 ALLOW | 0.4857 | 0.5405 | 0.5713 | 0.7149 |
| InjecAgent base | MiniLM ON | 0/1054 (0.00%) | 0/1054 (0.00%) | n/a | 15/1054 | +0 non-ALLOW, +0 ALLOW | 19.2399 | 43.8596 | 53.7841 | 66.4392 |
| PINT format smoke test | OFF | 1/2 (50.00%) | 0/1 (0.00%) | 0/6 (0.00%) | 0/8 | baseline | 0.2137 | 0.3612 | 0.4876 | 0.5887 |
| PINT format smoke test | TF-IDF ON | 1/2 (50.00%) | 0/1 (0.00%) | 0/6 (0.00%) | 1/8 | +0 non-ALLOW, +0 ALLOW | 0.9362 | 1.6520 | 1.8858 | 2.0728 |
| PINT format smoke test | MiniLM ON | 1/2 (50.00%) | 0/1 (0.00%) | 0/6 (0.00%) | 1/8 | +0 non-ALLOW, +0 ALLOW | 46.6057 | 56.5368 | 58.7736 | 60.5630 |

## InjecAgent split results

| Scanner | Direct harm caught | Direct harm SDK signaled | Data stealing caught | Data stealing SDK signaled |
| --- | ---: | ---: | ---: | ---: |
| OFF | 0/510 | 0/510 | 0/544 | 0/544 |
| TF-IDF ON | 0/510 | 19/510 | 0/544 | 0/544 |
| MiniLM ON | 0/510 | 15/510 | 0/544 | 0/544 |

## InjecAgent tool authorization

| Attack cases prevented | Attacker calls blocked | Legitimate calls allowed | Distinct attacker tools | Distinct legitimate tools |
| ---: | ---: | ---: | ---: | ---: |
| 1054/1054 (100.00%) | 1581/1598 (98.94%) | 1054/1054 (100.00%) | 63 | 17 |

| Tool call type | P50 ms | P90 ms | P95 ms | P99 ms |
| --- | ---: | ---: | ---: | ---: |
| attacker | 0.1265 | 0.1359 | 0.1450 | 0.2542 |
| legitimate | 0.1374 | 0.1508 | 0.1639 | 0.3219 |

This is a model-free authorization replay through `on_tool_call`. The 17 dataset user tools were allowed in both sidecar config layers. Legitimate calls used dataset parameters. Attacker calls used empty parameters because InjecAgent does not provide attacker call parameters

An attack case counts as prevented when at least 1 required attacker tool call returns BLOCK. The global legitimate and attacker tool sets overlap on GitHubGetUserDetails

The 17 attacker calls to `GitHubGetUserDetails` returned ALLOW because that name is also in the legitimate allowlist. Each paired `GmailSendEmail` call returned BLOCK

| Authorization provenance | SHA256 |
| --- | --- |
| Outcome | `ee42d56d55a37c9639a9a50f901c87cbaf12f6844640d4c08f52b5d27fff7363` |
| Sidecar config | `e26fb4d6170f55d635ce2e701ad9bd5ccd7ec8fdb8ecee374ce54c71c32d26db` |
| Policy config | `ee757976c9b47974d535f8684e4c4330dd99091ee4920d34fc3400c70695c653` |

## Interpretation

InjecAgent maps injected tool responses to `on_context` because ACF v1 has no `on_tool_result` hook. All 1054 cases are attacks, so InjecAgent does not provide a false-positive rate

For InjecAgent, TF-IDF emitted SDK signals on 19/1054 cases and MiniLM emitted SDK signals on 15/1054 cases. Across both ON runs, 0 final verdicts changed. The signaled categories with no sidecar weight or direct rule in `context.rego` were `encoding_evasion`, `role_hijack`, `tool_abuse`

For the PINT format sample, TF-IDF emitted SDK signals on 1/8 cases and MiniLM emitted SDK signals on 1/8 cases. Across both ON runs, 0 final verdicts changed. TF-IDF: `tool_abuse` had no sidecar weight or direct rule in `prompt.rego`. MiniLM: `instruction_override` had a sidecar weight and direct rule in `prompt.rego`

The public PINT file is a format sample, not the full benchmark. OFF caught 1/2 attacks, and 1 caught attack had an exact pattern overlap. After excluding exact overlaps, it caught 0/1 attacks with 0/6 benign false positives. The semantic library names PINT as a source, so the overlap-excluded result is not a held-out set

All latency values are local descriptive measurements. Raw timing files are not committed, so rerun the pinned commands to reproduce them on another machine

PINT latency percentiles are descriptive only because the public sample has 8 cases

## Run provenance

| Runtime field | Value |
| --- | --- |
| Platform | `macOS-26.5.2-arm64-arm-64bit-Mach-O` |
| Python | `3.14.2` |
| Go | `go version go1.25.6 darwin/arm64` |
| Concurrency | `1` sequential call per case |
| Runner commit | `91149556eab575c8c0bd31fae7b655cf17153139` |
| Runner SHA256 | `0c901c5b0ec638646148d1458dc3f35a6453f203d9db0de551533649fcfb984a` |
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
