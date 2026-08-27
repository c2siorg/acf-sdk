# External benchmark evaluation

ACF commit: `1fa1b402a5378f02883136eebf5e32318e8e623a`

These are detector catch rates through live ACF hooks and the Go sidecar. They are not agent attack success rates

| Dataset | Scanner | Attack detection | Overlap-excluded detection | Benign false positives | SDK signaled | Verdict lift vs OFF | P50 ms | P90 ms | P95 ms | P99 ms |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| InjecAgent base | OFF | 0/1054 (0.00%) | 0/1054 (0.00%) | n/a | 0/1054 | baseline | 0.1670 | 0.1946 | 0.2071 | 0.2689 |
| InjecAgent base | TF-IDF ON | 0/1054 (0.00%) | 0/1054 (0.00%) | n/a | 19/1054 | +0 non-ALLOW, +0 ALLOW | 0.5112 | 0.6036 | 0.6745 | 0.9786 |
| InjecAgent base | MiniLM ON | 0/1054 (0.00%) | 0/1054 (0.00%) | n/a | 15/1054 | +0 non-ALLOW, +0 ALLOW | 18.5964 | 45.2322 | 59.8227 | 88.6524 |
| PINT format smoke test | OFF | 1/2 (50.00%) | 0/1 (0.00%) | 0/6 (0.00%) | 0/8 | baseline | 0.2347 | 0.3727 | 0.4930 | 0.5893 |
| PINT format smoke test | TF-IDF ON | 1/2 (50.00%) | 0/1 (0.00%) | 0/6 (0.00%) | 1/8 | +0 non-ALLOW, +0 ALLOW | 0.7093 | 1.1052 | 1.4445 | 1.7160 |
| PINT format smoke test | MiniLM ON | 1/2 (50.00%) | 0/1 (0.00%) | 0/6 (0.00%) | 1/8 | +0 non-ALLOW, +0 ALLOW | 45.0153 | 50.2025 | 54.8405 | 58.5509 |

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
| attacker | 0.1286 | 0.1436 | 0.1516 | 0.2536 |
| legitimate | 0.1398 | 0.1547 | 0.1678 | 0.2731 |

This is a model-free authorization replay through `on_tool_call`. The 17 dataset user tools were allowed in both sidecar config layers. Legitimate calls used dataset parameters. Attacker calls used empty parameters because InjecAgent does not provide attacker call parameters

The runner builds the allowlist from the sorted unique `User Tool` values in the selected InjecAgent rows: `AmazonGetProductDetails`, `EvernoteManagerSearchNotes`, `GitHubGetRepositoryDetails`, `GitHubGetUserDetails`, `GitHubSearchRepositories`, `GmailReadEmail`, `GmailSearchEmails`, `GoogleCalendarGetEventsFromSharedCalendar`, `GoogleCalendarReadEvents`, `ShopifyGetProductDetails`, `TeladocViewReviews`, `TodoistSearchTasks`, `TwilioGetReceivedSmsMessages`, `TwitterManagerGetUserProfile`, `TwitterManagerReadTweet`, `TwitterManagerSearchTweets`, `WebBrowserNavigateTo`. The same dataset supplies the test cases and the allowed tool names. The 100% legitimate-tool result is expected at the name check, though parameter scans and policy rules can still block a call. This can look better than a deployment with an independently chosen allowlist. It does not test allowlist selection or a new legitimate tool

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
| Runner commit | `85954ed6ce0b4cc89a8ee8304eaa1dd2619216f5` |
| Runner SHA256 | `d37a042071b767e85415ae21dda16e501c67caf2cb71793ae8b042f2b3b6b909` |
| Manifest SHA256 | `b6df0ccf4d35e54d5afbe7b9005beb3eda93cd0e18d1ef55830e866a0875a616` |

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
