/**
 * tests/helpers.ts
 * ================
 * Shared test utilities.
 * Imported by every test file — no external test framework needed.
 */


// @ts-ignore - Buffer is a global in Node.js
import { Buffer } from "buffer"

/**
 * Fixed 32-byte test key — matches the Python and Go test suites exactly.
 * Using the same key across all three SDKs means cross-SDK HMAC tests
 * can assert identical outputs without coordination.
 */
export const TEST_KEY = Buffer.from(
    "test-key-32-bytes-long-padded!!!",
    "utf-8"
)

/**
 * Fixed 16-byte nonce for deterministic cross-SDK interop tests.
 * Production nonces are random — this is only for testing.
 */
export const FIXED_NONCE = Buffer.from([
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
])