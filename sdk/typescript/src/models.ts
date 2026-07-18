/**
 * Data models for the ACF TypeScript SDK (v2 — deferred).
 * Decision, SanitiseResult, ChunkResult types mirror the Python SDK models.
 * Same wire protocol as Python v1.
 */
/**
 * models.ts
 * =========
 * Data models for the ACF TypeScript SDK.
 * Mirrors sdk/python/acf/models.py exactly.
 *
 * Decision byte values match the wire protocol defined in
 * sidecar/internal/transport/frame.go — never change these values.
 */

// ── Decision ──────────────────────────────────────────────────────────────────

/**
 * The three possible enforcement outcomes returned by all hook calls.
 * Byte values match the wire protocol exactly.
 */
export enum Decision {
    ALLOW    = 0x00,
    SANITISE = 0x01,
    BLOCK    = 0x02,
}

/**
 * Parse a raw response byte into a Decision.
 * Throws RangeError for any unrecognised byte.
 */
export function decisionFromByte(b: number): Decision {
    switch (b) {
        case 0x00: return Decision.ALLOW
        case 0x01: return Decision.SANITISE
        case 0x02: return Decision.BLOCK
        default:
            throw new RangeError(
                `Unknown decision byte: 0x${b.toString(16).padStart(2, "0")}`
            )
    }
}

// ── Result types ──────────────────────────────────────────────────────────────

/**
 * Returned when the sidecar decides SANITISE.
 * Use sanitisedText in place of the original input.
 */
export interface SanitiseResult {
    readonly decision:         Decision.SANITISE
    readonly sanitisedPayload: Uint8Array
    readonly sanitisedText:    string | null
}

/**
 * Per-chunk result returned by Firewall.onContext().
 * One ChunkResult is returned per input chunk.
 */
export interface ChunkResult {
    readonly original:      string
    readonly decision:      Decision
    readonly sanitisedText: string | null
}

// ── Errors ────────────────────────────────────────────────────────────────────

/**
 * Base error class for all ACF SDK errors.
 * Catch this to handle any SDK failure in one place.
 */
export class FirewallError extends Error {
    constructor(message: string) {
        super(message)
        this.name = "FirewallError"
        // Maintains proper stack trace in V8
        if ((Error as any).captureStackTrace) {
            (Error as any).captureStackTrace(this, FirewallError)
        }
    }
}

/**
 * Raised when the transport cannot connect to the sidecar after all retries.
 * Subclasses FirewallError — callers catching FirewallError see this too.
 */
export class FirewallConnectionError extends FirewallError {
    constructor(message: string) {
        super(message)
        this.name = "FirewallConnectionError"
        if ((Error as any).captureStackTrace) {
            (Error as any).captureStackTrace(this, FirewallConnectionError)
        }
    }
}