/// <reference types="node" />

import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { createHmac } from "node:crypto"

import { FIXED_NONCE, TEST_KEY } from "./helpers.js"
import {
    CanonicaliseError,
    FrameError,
    HEADER_SIZE,
    MAGIC,
    VERSION,
    canonicalPayload,
    decodeRequest,
    decodeResponse,
    encodeRequest,
    encodeResponse,
    signedMessage,
} from "../src/frame.js"

describe("canonicalPayload", () => {
    it("sorts keys recursively for nested objects", () => {
        const input = Buffer.from('{"z":{"b":2,"a":1},"a":0}')
        const out = canonicalPayload(input)
        assert.strictEqual(out.toString("utf-8"), '{"a":0,"z":{"a":1,"b":2}}')
    })

    it("is idempotent", () => {
        const input = Buffer.from('{"b":2,"a":1}')
        const once = canonicalPayload(input)
        const twice = canonicalPayload(once)
        assert.deepStrictEqual(twice, once)
    })

    it("normalizes unicode escapes via JSON parsing", () => {
        const input = Buffer.from('{"key":"\\u0041"}')
        const out = canonicalPayload(input)
        assert.strictEqual(out.toString("utf-8"), '{"key":"A"}')
    })

    it("throws CanonicaliseError on invalid JSON", () => {
        assert.throws(
            () => canonicalPayload(Buffer.from("{not-json")),
            CanonicaliseError,
        )
    })

    it("CanonicaliseError is caught as FrameError", () => {
        assert.throws(
            () => canonicalPayload(Buffer.from("{not-json")),
            FrameError,
        )
    })
})

describe("signedMessage", () => {
    it("produces identical bytes for equivalent payload key orders", () => {
        const p1 = canonicalPayload(Buffer.from('{"b":2,"a":1}'))
        const p2 = canonicalPayload(Buffer.from('{"a":1,"b":2}'))
        const m1 = signedMessage(VERSION, p1.length, FIXED_NONCE, p1)
        const m2 = signedMessage(VERSION, p2.length, FIXED_NONCE, p2)
        assert.deepStrictEqual(m1, m2)
    })

    it("throws FrameError when nonce is wrong length", () => {
        assert.throws(
            () => signedMessage(VERSION, 0, Buffer.alloc(8), Buffer.alloc(0)),
            FrameError,
        )
    })

    it("produces identical HMAC for equivalent payload key orders — core cross-SDK guarantee", () => {
        const pythonStyle = Buffer.from('{"hook_type":"on_prompt","score":0.0,"payload":"hello"}')
        const typescriptStyle = Buffer.from('{"payload":"hello","score":0.0,"hook_type":"on_prompt"}')

        const canon1 = canonicalPayload(pythonStyle)
        const canon2 = canonicalPayload(typescriptStyle)

        const msg1 = signedMessage(VERSION, canon1.length, FIXED_NONCE, canon1)
        const msg2 = signedMessage(VERSION, canon2.length, FIXED_NONCE, canon2)

        const hmac1 = createHmac("sha256", TEST_KEY).update(msg1).digest()
        const hmac2 = createHmac("sha256", TEST_KEY).update(msg2).digest()

        assert.deepStrictEqual(
            hmac1,
            hmac2,
            "HMAC mismatch for semantically identical JSON with different key order",
        )
    })
})

describe("encodeRequest/decodeRequest", () => {
    it("encodes valid request header fields", () => {
        const frame = encodeRequest(Buffer.from('{"b":2,"a":1}'), TEST_KEY)
        assert.strictEqual(frame[0], MAGIC)
        assert.strictEqual(frame[1], VERSION)
    })

    it("uses canonical payload length in length field", () => {
        const raw = Buffer.from('{"b":2,"a":1}')
        const canonical = canonicalPayload(raw)
        const frame = encodeRequest(raw, TEST_KEY)
        const length = frame.readUInt32BE(2)
        assert.strictEqual(length, canonical.length)
    })

    it("encodes a verifiable HMAC over canonical payload", () => {
        const frame = encodeRequest(Buffer.from('{"b":2,"a":1}'), TEST_KEY)
        const req = decodeRequest(frame)
        const msg = signedMessage(req.version, req.payload.length, req.nonce, req.payload)
        const expected = createHmac("sha256", TEST_KEY).update(msg).digest()
        assert.deepStrictEqual(req.hmac, expected)
    })

    it("decodeRequest returns canonical payload bytes", () => {
        const frame = encodeRequest(Buffer.from('{"b":2,"a":1}'), TEST_KEY)
        const req = decodeRequest(frame)
        assert.strictEqual(req.payload.toString("utf-8"), '{"a":1,"b":2}')
    })

    it("rejects bad magic", () => {
        const frame = Buffer.from(encodeRequest(Buffer.from("{}"), TEST_KEY))
        frame[0] = 0xFF
        assert.throws(() => decodeRequest(frame), FrameError)
    })

    it("rejects bad version", () => {
        const frame = Buffer.from(encodeRequest(Buffer.from("{}"), TEST_KEY))
        frame[1] = 0x02
        assert.throws(() => decodeRequest(frame), FrameError)
    })

    it("rejects truncated frame header", () => {
        assert.throws(
            () => decodeRequest(Buffer.from([MAGIC, VERSION, 0x00])),
            FrameError,
        )
    })

    it("rejects truncated payload", () => {
        const frame = Buffer.from(encodeRequest(Buffer.from('{"a":1}'), TEST_KEY))
        const length = frame.readUInt32BE(2)
        assert(length > 0)
        const short = frame.subarray(0, HEADER_SIZE + length - 1)
        assert.throws(() => decodeRequest(short), FrameError)
    })
})

describe("encodeResponse/decodeResponse", () => {
    it("round-trips ALLOW", () => {
        const encoded = encodeResponse(0x00)
        const decoded = decodeResponse(encoded)
        assert.strictEqual(decoded.decision, 0x00)
        assert.deepStrictEqual(decoded.sanitisedPayload, Buffer.alloc(0))
    })

    it("round-trips BLOCK", () => {
        const encoded = encodeResponse(0x02)
        const decoded = decodeResponse(encoded)
        assert.strictEqual(decoded.decision, 0x02)
        assert.deepStrictEqual(decoded.sanitisedPayload, Buffer.alloc(0))
    })

    it("round-trips SANITISE with payload", () => {
        const body = Buffer.from("safe content")
        const encoded = encodeResponse(0x01, body)
        const decoded = decodeResponse(encoded)
        assert.strictEqual(decoded.decision, 0x01)
        assert.deepStrictEqual(decoded.sanitisedPayload, body)
    })

    it("rejects truncated response header", () => {
        assert.throws(() => decodeResponse(Buffer.from([0x00, 0x00])), FrameError)
    })

    it("rejects truncated sanitised payload body", () => {
        const encoded = encodeResponse(0x01, Buffer.from("hello"))
        const short = encoded.subarray(0, encoded.length - 1)
        assert.throws(() => decodeResponse(short), FrameError)
    })
})
