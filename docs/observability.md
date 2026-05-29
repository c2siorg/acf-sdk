# Observability

Phase 2 introduces two telemetry surfaces on the sidecar:

1. OpenTelemetry spans per pipeline run plus one child span per stage
2. A structured JSON audit log with one line per enforcement decision

Both are decoupled from enforcement: the decision the PDP returns is identical
whether telemetry is on or off. An empty `otel_endpoint` installs a noop tracer.
The audit log defaults to stdout so the audit trail is on by default; set
`audit_path` to redirect it to a file, and if that path cannot be opened the sink
falls back to a noop rather than stopping the sidecar.

## Running the local stack

The repo ships an opt-in docker compose profile that brings up an OpenTelemetry
collector and a Jaeger all-in-one. The sidecar service is unaffected when the
profile is not active.

```bash
docker compose --profile observability up -d
```

The sidecar then needs to know where to send spans. Add a telemetry block to
`config/sidecar.yaml`:

```yaml
telemetry:
  otel_endpoint: http://otel-collector:4318
  sample_ratio: 1.0
  service_name: acf-sidecar
  insecure: true
  audit_path: /var/log/acf/audit.log
  audit_buffer: 1024
  policy_version: v1
```

Once spans land, open http://localhost:16686 and pick `acf-sidecar` in the
service dropdown. Every `pipeline.Run` appears as a root span with one child
per stage

## Span layout

One run through the PDP produces the following trace shape:

```
pipeline.Run              hook_type, provenance, decision, score, duration_ms
├── stage.validate        signals.added, hard_block
├── stage.normalise       signals.added, hard_block
├── stage.scan            signals.added, hard_block
├── stage.aggregate       signals.added, hard_block
└── opa.evaluate          opa.input.hook_type, opa.input.score, opa.input.signals,
                          opa.output.decision, opa.output.sanitise_targets
```

`signals.added` is the number of new signal names the stage emitted during
the run. `hard_block` is true when the stage tripped a hard block signal.
Root span attributes are populated after stage iteration finishes so they
reflect the final decision rather than intermediate state

`opa.evaluate` wraps the policy decision. Its `opa.input.*` attributes record
what the pipeline hands OPA (the hook type, aggregate score, and signal count)
and its `opa.output.*` attributes record what OPA returns (the decision and how
many sanitise targets it declared). The span is created whenever an OPA
evaluator is configured, and on an evaluator error it records the error before
the pipeline falls back to threshold scoring. It is skipped only when no
evaluator is set, or when a strict-mode hard block short-circuits before the
decision step. As with every span, only metadata is recorded, never raw payload
or canonical text

The sampler is `ParentBased(TraceIDRatioBased(sample_ratio))`. When the
caller passes a context that already carries a sampled trace (for example
when the transport listener gains trace context propagation), the sidecar
honours that upstream decision instead of applying its own ratio.

## Audit log schema

Every run emits one JSON object on its own line. Field order is stable.

```json
{
  "ts": "2026-04-14T11:05:41.923Z",
  "trace_id": "6e8a0c8f...",
  "span_id": "9f1a2b3c...",
  "hook_type": "on_prompt",
  "decision": "block",
  "score": 0.91,
  "signals": ["jailbreak_pattern"],
  "provenance": "user",
  "session_id": "sess-42",
  "policy_version": "v1",
  "blocked_at": "scan",
  "duration_ms": 1.7
}
```

Fields map directly to the doc block in `sidecar/internal/telemetry/audit.go`.
`trace_id` and `span_id` are omitted when tracing is off, and `blocked_at`
is omitted for runs that completed without a hard block

## Privacy guarantees

The audit writer and the span attributes never record:

- `RiskContext.Payload` (the raw content)
- `RiskContext.CanonicalText` (the normalised text the scanner operates on)
- Any substring of user input beyond the controlled signal vocabulary

Only decision metadata, named signals, and timing land in the sinks. This
matches the spirit of the OWASP LLM Top 10 prompt-leakage guidance applied
to a PDP: we want replayability and SLO monitoring, not a copy of every
prompt we ever evaluated

## Failure modes

- **Collector unreachable at startup.** `telemetry.Init` logs a warning and
  installs a noop tracer. Enforcement continues unaffected
- **Collector goes down after startup.** The batch exporter buffers
  internally and silently drops spans when its buffer is full. The PDP is
  not stalled
- **Audit sink backpressure.** The async writer uses a non-blocking send on
  a buffered channel. Entries are dropped and the `Dropped()` counter
  advances; the enforcement path is unaffected
- **Invalid endpoint URL.** Logged at startup, falls back to noop. The
  sidecar still serves traffic

## Tuning

- `sample_ratio` controls head-based sampling. `1.0` samples everything;
  `0.0` disables span emission entirely. The literal zero is honoured, so
  operators can leave the block configured but turn spans off
- `audit_buffer` sets the async audit channel depth. The default (1024) is
  tuned for low-latency local development. Production deployments that
  expect sustained high QPS should raise it to keep the drop counter at
  zero under peak
- `audit_path` routes audit lines to a file. Parent directories are
  created on startup. Rotate externally (logrotate, kubernetes pod logs).
  Leave empty or use `-` for stdout

## Benchmarks

From `go test -bench=. -benchmem -run=^$ ./internal/pipeline/...`:

| Configuration          | ns/op | B/op | allocs/op |
|------------------------|-------|------|-----------|
| No telemetry           | ~1200 | ~2600 | ~31 |
| Audit only             | ~1700 | ~2830 | ~33 |
| Tracer + audit (noop)  | ~1735 | ~2830 | ~33 |

Absolute numbers depend on hardware. The delta between configurations is
what matters: around 500 ns added by the audit writer, and a further
negligible cost for the noop tracer. Under real scan workloads (Aho-Corasick
over kilobytes of text) the relative telemetry overhead drops below five
percent
