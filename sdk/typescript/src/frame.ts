
/**
 * Binary frame encoder/decoder using Node.js Buffer.
 * Mirrors sidecar/internal/transport/frame.go and sdk/python/acf/frame.py.
 *
 * Request frame layout (54-byte header + payload):
 *   [0]      magic     — 0xAC
 *   [1]      version   — 1
 *   [2:6]    length    — uint32 big-endian
 *   [6:22]   nonce     — 16 random bytes
 *   [22:54]  hmac      — 32 bytes HMAC-SHA256 over signedMessage(...)
 *   [54:]    payload   — JSON bytes
 *
 * Response frame layout:
 *   [0]      decision  — 0x00 ALLOW · 0x01 SANITISE · 0x02 BLOCK
 *   [1:5]    san_len   — uint32 big-endian (0 if not SANITISE)
 *   [5:]     sanitised — JSON bytes (SANITISE only)
 */

import { createHmac, randomBytes } from "node:crypto"

export const MAGIC = 0xAC
export const VERSION = 0x01
export const HEADER_SIZE = 54 // 1 + 1 + 4 + 16 + 32

export interface RequestFrame {
    readonly version: number
    readonly nonce: Buffer
    readonly hmac: Buffer
    readonly payload: Buffer
}

export interface ResponseFrame {
    readonly decision: number
    readonly sanitisedPayload: Buffer
}

export class FrameError extends Error {
    constructor(message: string) {
        super(message)
        this.name = "FrameError"
        if ((Error as any).captureStackTrace) {
            (Error as any).captureStackTrace(this, FrameError)
        }
    }
}

export class CanonicaliseError extends FrameError {
    constructor(message: string) {
        super(message)
        this.name = "CanonicaliseError"
        if ((Error as any).captureStackTrace) {
            (Error as any).captureStackTrace(this, CanonicaliseError)
        }
    }
}

/**
 * Recursively sort object keys at every nesting level.
 * Arrays preserve order. Primitives pass through.
 */
export function sortKeysRecursive(value: unknown): unknown {
    if (Array.isArray(value)) {
        return value.map((item) => sortKeysRecursive(item))
    }

    if (value !== null && typeof value === "object") {
        const out: Record<string, unknown> = {}
        const entries = Object.entries(value as Record<string, unknown>)
        entries
            .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
            .forEach(([k, v]) => {
                out[k] = sortKeysRecursive(v)
            })
        return out
    }

    // JSON.parse already resolves \uXXXX escapes to the literal code point.
    // Keep primitive values unchanged for parity with Python/Go JSON handling.
    return value
}

/**
 * Parse, recursively canonicalise (sorted keys), and compact-encode JSON.
 */
export function canonicalPayload(payload: Buffer): Buffer {
    let parsed: unknown
    try {
        parsed = JSON.parse(payload.toString("utf-8"))
    } catch (err) {
        const reason = err instanceof Error ? err.message : String(err)
        throw new CanonicaliseError(`invalid JSON payload: ${reason}`)
    }

    const canonical = sortKeysRecursive(parsed)
    return Buffer.from(JSON.stringify(canonical), "utf-8")
}

/**
 * version(1B) || length(4B BE) || nonce(16B) || payload
 */
export function signedMessage(
    version: number,
    length: number,
    nonce: Buffer,
    payload: Buffer,
): Buffer {
    if (nonce.length !== 16) {
        throw new FrameError(`nonce must be 16 bytes, got ${nonce.length}`)
    }

    const header = Buffer.allocUnsafe(21)
    header.writeUInt8(version, 0)
    header.writeUInt32BE(length, 1)
    nonce.copy(header, 5)
    return Buffer.concat([header, payload], 21 + payload.length)
}

export function encodeRequest(payload: Buffer, key: Buffer): Buffer {
    const canonical = canonicalPayload(payload)
    const nonce = randomBytes(16)
    const length = canonical.length
    const msg = signedMessage(VERSION, length, nonce, canonical)
    const mac = createHmac("sha256", key).update(msg).digest()

    const header = Buffer.allocUnsafe(HEADER_SIZE)
    header.writeUInt8(MAGIC, 0)
    header.writeUInt8(VERSION, 1)
    header.writeUInt32BE(length, 2)
    nonce.copy(header, 6)
    mac.copy(header, 22)
    return Buffer.concat([header, canonical], HEADER_SIZE + canonical.length)
}

export function decodeRequest(data: Buffer): RequestFrame {
    if (data.length < HEADER_SIZE) {
        throw new FrameError(
            `truncated frame: got ${data.length} bytes, need at least ${HEADER_SIZE}`
        )
    }

    const magic = data.readUInt8(0)
    if (magic !== MAGIC) {
        throw new FrameError(
            `bad magic byte: got 0x${magic.toString(16).padStart(2, "0")}, want 0x${MAGIC.toString(16)}`
        )
    }

    const version = data.readUInt8(1)
    if (version !== VERSION) {
        throw new FrameError(`unsupported version: ${version}`)
    }

    const length = data.readUInt32BE(2)
    const end = HEADER_SIZE + length
    if (data.length < end) {
        throw new FrameError(
            `truncated payload: got ${data.length - HEADER_SIZE} bytes, want ${length}`
        )
    }

    return {
        version,
        nonce: Buffer.from(data.subarray(6, 22)),
        hmac: Buffer.from(data.subarray(22, 54)),
        payload: Buffer.from(data.subarray(54, end)),
    }
}

export function encodeResponse(decision: number, sanitised: Buffer = Buffer.alloc(0)): Buffer {
    const sanLen = decision === 0x01 ? sanitised.length : 0
    const header = Buffer.allocUnsafe(5)
    header.writeUInt8(decision, 0)
    header.writeUInt32BE(sanLen, 1)
    if (sanLen === 0) {
        return header
    }
    return Buffer.concat([header, sanitised.subarray(0, sanLen)], 5 + sanLen)
}

export function decodeResponse(data: Buffer): ResponseFrame {
    if (data.length < 5) {
        throw new FrameError(
            `truncated response: got ${data.length} bytes, need at least 5`
        )
    }

    const decision = data.readUInt8(0)
    const sanLen = data.readUInt32BE(1)
    const end = 5 + sanLen
    if (data.length < end) {
        throw new FrameError(
            `truncated sanitised payload: got ${data.length - 5} bytes, want ${sanLen}`
        )
    }

    return {
        decision,
        sanitisedPayload: sanLen > 0 ? Buffer.from(data.subarray(5, end)) : Buffer.alloc(0),
    }
}
