/// <reference types="node" />

import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { EventEmitter } from "node:events"

import { encodeResponse } from "../src/frame.js"
import {
    BACKOFF_BASE_MS,
    MAX_ATTEMPTS,
    Transport,
} from "../src/transport.js"
import { FirewallConnectionError, FirewallError } from "../src/models.js"
import { TEST_KEY } from "./helpers.js"

class ScriptedTransport extends Transport {
    attempts = 0

    constructor(
        socketPath: string,
        key: Buffer,
        private readonly script: Array<() => Promise<Buffer>>,
    ) {
        super(socketPath, key)
    }

    protected override async connectAndSend(_frame: Buffer): Promise<Buffer> {
        this.attempts += 1
        const step = this.script[this.attempts - 1]
        if (!step) {
            throw new Error("script exhausted unexpectedly")
        }
        return step()
    }
}

function errnoError(code: string, message: string): Error & { code: string } {
    const err = new Error(message) as Error & { code: string }
    err.code = code
    return err
}

class FakeSocket extends EventEmitter {
    readonly writes: Buffer[] = []
    destroyed = false

    write(
        data: Buffer | Uint8Array,
        cb?: ((err?: Error | null) => void) | undefined,
    ): boolean {
        this.writes.push(Buffer.from(data))
        if (cb) {
            cb(undefined)
        }
        return true
    }

    destroy(): this {
        this.destroyed = true
        return this
    }
}

describe("Transport retry behavior", () => {
    it("retries on ECONNREFUSED then succeeds", async () => {
        const t = new ScriptedTransport("/tmp/acf.sock", TEST_KEY, [
            async () => { throw errnoError("ECONNREFUSED", "refused") },
            async () => encodeResponse(0x00),
        ])

        const started = Date.now()
        const result = await t.send(Buffer.from("{}"))
        const elapsed = Date.now() - started

        assert.strictEqual(result.decision, 0x00)
        assert.strictEqual(t.attempts, 2)
        assert(elapsed >= BACKOFF_BASE_MS)
    })

    it("retries on ENOENT then succeeds", async () => {
        const t = new ScriptedTransport("/tmp/acf.sock", TEST_KEY, [
            async () => { throw errnoError("ENOENT", "missing socket") },
            async () => encodeResponse(0x02),
        ])

        const result = await t.send(Buffer.from("{}"))

        assert.strictEqual(result.decision, 0x02)
        assert.strictEqual(t.attempts, 2)
    })

    it("throws FirewallConnectionError after retry exhaustion", async () => {
        const t = new ScriptedTransport("/tmp/acf.sock", TEST_KEY, [
            async () => { throw errnoError("ENOENT", "missing") },
            async () => { throw errnoError("ECONNREFUSED", "refused") },
            async () => { throw errnoError("ENOENT", "still missing") },
        ])

        await assert.rejects(
            () => t.send(Buffer.from("{}")),
            FirewallConnectionError,
        )
        assert.strictEqual(t.attempts, MAX_ATTEMPTS)
    })

    it("does not retry non-transient errors", async () => {
        const t = new ScriptedTransport("/tmp/acf.sock", TEST_KEY, [
            async () => { throw errnoError("EACCES", "permission denied") },
        ])

        await assert.rejects(
            () => t.send(Buffer.from("{}")),
            FirewallError,
        )
        assert.strictEqual(t.attempts, 1)
    })
})

describe("Transport socket read path", () => {
    it("reads ALLOW response from a socket stream", async () => {
        const fake = new FakeSocket()
        const t = new Transport(
            "/tmp/acf.sock",
            TEST_KEY,
            () => fake as unknown as import("node:net").Socket,
        )

        queueMicrotask(() => {
            fake.emit("connect")
            fake.emit("data", encodeResponse(0x00))
        })

        const result = await t.send(Buffer.from('{"b":2,"a":1}'))

        assert.strictEqual(result.decision, 0x00)
        assert.deepStrictEqual(result.sanitisedPayload, Buffer.alloc(0))
        assert.strictEqual(fake.destroyed, true)
    })

    it("reassembles fragmented SANITISE responses from chunked data events", async () => {
        const body = Buffer.from("safe content")
        const encoded = encodeResponse(0x01, body)
        const fake = new FakeSocket()
        const t = new Transport(
            "/tmp/acf.sock",
            TEST_KEY,
            () => fake as unknown as import("node:net").Socket,
        )

        queueMicrotask(() => {
            fake.emit("connect")
            fake.emit("data", encoded.subarray(0, 2))
            fake.emit("data", encoded.subarray(2, 5))
            fake.emit("data", encoded.subarray(5))
        })

        const result = await t.send(Buffer.from("{}"))

        assert.strictEqual(result.decision, 0x01)
        assert.deepStrictEqual(result.sanitisedPayload, body)
        assert.strictEqual(fake.destroyed, true)
    })

    it("fails when socket closes before full response is read", async () => {
        const fake = new FakeSocket()
        const t = new Transport(
            "/tmp/acf.sock",
            TEST_KEY,
            () => fake as unknown as import("node:net").Socket,
        )

        queueMicrotask(() => {
            fake.emit("connect")
            fake.emit("data", Buffer.from([0x01, 0x00])) // partial header
            fake.emit("close")
        })

        await assert.rejects(
            () => t.send(Buffer.from("{}")),
            FirewallError,
        )
    })
})
