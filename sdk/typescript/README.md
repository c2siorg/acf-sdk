# ACF TypeScript SDK

TypeScript client for ACF-SDK (Agentic Cognitive Firewall).

This SDK sends signed risk-context payloads over IPC to the Go sidecar and
returns enforcement decisions:

- `ALLOW`
- `SANITISE`
- `BLOCK`

## Prerequisites

- Node.js 18+
- Go sidecar built and running

## Install

From `sdk/typescript`:

```bash
npm ci
npm run build
```

## Configuration

The firewall requires a shared HMAC key:

```bash
export ACF_HMAC_KEY=<64-hex-char-key>
```

Optional custom socket path:

```bash
export ACF_SOCKET_PATH=/tmp/acf.sock
```

## Quick Start

```ts
import { Firewall, Decision } from "@acf-sdk/acf"

const fw = new Firewall()
const result = await fw.onPrompt("hello world")

if (result === Decision.BLOCK) {
  throw new Error("Blocked by firewall")
}
```

## Test Commands

From `sdk/typescript`:

```bash
# Unit tests (fast, default)
npm test

# Live sidecar E2E tests
npm run test:e2e

# TypeScript/Python parity tests against live sidecar
npm run test:parity
```

## Troubleshooting

### `No HMAC key provided`

Set `ACF_HMAC_KEY` or pass key bytes directly:

```ts
const fw = new Firewall(undefined, Buffer.from("<hex>", "hex"))
```

### Sidecar not reachable

- Ensure sidecar is running.
- Ensure `ACF_SOCKET_PATH` matches both sidecar and SDK.
- Ensure SDK and sidecar use the same `ACF_HMAC_KEY`.

### E2E tests skipped in sandboxed environments

Some environments disallow Unix socket bind/listen. E2E/parity tests will skip
with a clear reason when this restriction is detected.

## Compatibility Contract

TypeScript and Python SDKs must remain wire-compatible:

- canonical JSON signing
- identical frame structure
- decision-level parity for shared scenarios
