/// <reference types="node" />

import { afterEach, describe, it } from "node:test"
import assert from "node:assert/strict"

import { Firewall } from "../src/firewall.js"
import { Decision, FirewallConnectionError, FirewallError } from "../src/models.js"
import type { ResponseFrame } from "../src/frame.js"

class FakeTransport {
    readonly seenPayloads: Buffer[] = []
    private readonly queue: Array<() => Promise<ResponseFrame>>

    constructor(queue: Array<() => Promise<ResponseFrame>>) {
        this.queue = queue
    }

    async send(payload: Buffer): Promise<ResponseFrame> {
        this.seenPayloads.push(Buffer.from(payload))
        const next = this.queue.shift()
        if (!next) {
            throw new Error("no scripted response")
        }
        return next()
    }
}

type FactoryCapture = {
    socketPath?: string
    key?: Buffer
    transport: FakeTransport
}

function makeFactory(
    queue: Array<() => Promise<ResponseFrame>>,
): { capture: FactoryCapture; factory: (socketPath?: string, key?: Buffer) => FakeTransport } {
    const capture: FactoryCapture = {
        socketPath: undefined,
        key: undefined,
        transport: new FakeTransport(queue),
    }

    return {
        capture,
        factory: (socketPath?: string, key?: Buffer) => {
            capture.socketPath = socketPath
            capture.key = key ? Buffer.from(key) : undefined
            return capture.transport
        },
    }
}

const ORIGINAL_KEY = process.env.ACF_HMAC_KEY
afterEach(() => {
    if (ORIGINAL_KEY === undefined) {
        delete process.env.ACF_HMAC_KEY
    } else {
        process.env.ACF_HMAC_KEY = ORIGINAL_KEY
    }
})

describe("Firewall constructor", () => {
    it("uses provided hmacKey over env value", () => {
        process.env.ACF_HMAC_KEY = "aaaaaaaa"
        const { capture, factory } = makeFactory([
            async () => ({ decision: 0x00, sanitisedPayload: Buffer.alloc(0) }),
        ])

        const provided = Buffer.from("00112233", "hex")
        new Firewall("/tmp/acf.sock", provided, factory)

        assert.strictEqual(capture.socketPath, "/tmp/acf.sock")
        assert.deepStrictEqual(capture.key, provided)
    })

    it("reads ACF_HMAC_KEY when key not provided", () => {
        process.env.ACF_HMAC_KEY = "0011223344556677"
        const { capture, factory } = makeFactory([
            async () => ({ decision: 0x00, sanitisedPayload: Buffer.alloc(0) }),
        ])

        new Firewall(undefined, undefined, factory)

        assert.deepStrictEqual(capture.key, Buffer.from("0011223344556677", "hex"))
    })

    it("throws FirewallError when no key is available", () => {
        delete process.env.ACF_HMAC_KEY
        const { factory } = makeFactory([])
        assert.throws(
            () => new Firewall(undefined, undefined, factory),
            FirewallError,
        )
    })

    it("throws FirewallError when env key is invalid hex", () => {
        process.env.ACF_HMAC_KEY = "zzzz"
        const { factory } = makeFactory([])
        assert.throws(
            () => new Firewall(undefined, undefined, factory),
            FirewallError,
        )
    })
})

describe("Firewall hook payloads and decisions", () => {
    it("onPrompt sends on_prompt payload and returns ALLOW", async () => {
        const { capture, factory } = makeFactory([
            async () => ({ decision: 0x00, sanitisedPayload: Buffer.alloc(0) }),
        ])
        const fw = new Firewall(
            undefined,
            Buffer.from("0011223344556677", "hex"),
            factory,
        )

        const result = await fw.onPrompt("hello")
        assert.strictEqual(result, Decision.ALLOW)
        assert.strictEqual(capture.transport.seenPayloads.length, 1)

        const payload = JSON.parse(capture.transport.seenPayloads[0].toString("utf-8"))
        assert.strictEqual(payload.hook_type, "on_prompt")
        assert.strictEqual(payload.provenance, "user")
        assert.strictEqual(payload.payload, "hello")
        assert.strictEqual(payload.score, 0)
        assert.deepStrictEqual(payload.signals, [])
        assert.strictEqual(payload.state, null)
    })

    it("onToolCall sends structured payload and returns BLOCK", async () => {
        const { capture, factory } = makeFactory([
            async () => ({ decision: 0x02, sanitisedPayload: Buffer.alloc(0) }),
        ])
        const fw = new Firewall(
            undefined,
            Buffer.from("0011223344556677", "hex"),
            factory,
        )

        const result = await fw.onToolCall("search", { q: "karachi weather" })
        assert.strictEqual(result, Decision.BLOCK)

        const payload = JSON.parse(capture.transport.seenPayloads[0].toString("utf-8"))
        assert.strictEqual(payload.hook_type, "on_tool_call")
        assert.strictEqual(payload.provenance, "agent")
        assert.deepStrictEqual(payload.payload, {
            name: "search",
            params: { q: "karachi weather" },
        })
    })

    it("onMemory defaults op to write", async () => {
        const { capture, factory } = makeFactory([
            async () => ({ decision: 0x00, sanitisedPayload: Buffer.alloc(0) }),
        ])
        const fw = new Firewall(
            undefined,
            Buffer.from("0011223344556677", "hex"),
            factory,
        )

        await fw.onMemory("pref", "dark")

        const payload = JSON.parse(capture.transport.seenPayloads[0].toString("utf-8"))
        assert.strictEqual(payload.hook_type, "on_memory")
        assert.deepStrictEqual(payload.payload, {
            key: "pref",
            value: "dark",
            op: "write",
        })
    })

    it("onMemory includes explicit op when provided", async () => {
        const { capture, factory } = makeFactory([
            async () => ({ decision: 0x00, sanitisedPayload: Buffer.alloc(0) }),
        ])
        const fw = new Firewall(
            undefined,
            Buffer.from("0011223344556677", "hex"),
            factory,
        )

        await fw.onMemory("pref", "dark", "read")

        const payload = JSON.parse(capture.transport.seenPayloads[0].toString("utf-8"))
        assert.deepStrictEqual(payload.payload, {
            key: "pref",
            value: "dark",
            op: "read",
        })
    })

    it("maps SANITISE response to SanitiseResult", async () => {
        const body = Buffer.from("safe content")
        const { factory } = makeFactory([
            async () => ({ decision: 0x01, sanitisedPayload: body }),
        ])
        const fw = new Firewall(
            undefined,
            Buffer.from("0011223344556677", "hex"),
            factory,
        )

        const result = await fw.onPrompt("test")
        assert.strictEqual(typeof result, "object")
        assert(result && typeof result === "object")
        if (typeof result === "object") {
            assert.strictEqual(result.decision, Decision.SANITISE)
            assert.strictEqual(result.sanitisedText, "safe content")
            assert.deepStrictEqual(Buffer.from(result.sanitisedPayload), body)
        }
    })

    it("maps empty SANITISE payload to sanitisedText null", async () => {
        const { factory } = makeFactory([
            async () => ({ decision: 0x01, sanitisedPayload: Buffer.alloc(0) }),
        ])
        const fw = new Firewall(
            undefined,
            Buffer.from("0011223344556677", "hex"),
            factory,
        )

        const result = await fw.onPrompt("test")
        assert(result && typeof result === "object")
        if (typeof result === "object") {
            assert.strictEqual(result.decision, Decision.SANITISE)
            assert.strictEqual(result.sanitisedText, null)
        }
    })
})

describe("Firewall onContext behavior", () => {
    it("returns empty array for empty chunks", async () => {
        const { factory } = makeFactory([])
        const fw = new Firewall(
            undefined,
            Buffer.from("0011223344556677", "hex"),
            factory,
        )
        const result = await fw.onContext([])
        assert.deepStrictEqual(result, [])
    })

    it("returns per-chunk decisions with sanitised text on SANITISE", async () => {
        const { factory } = makeFactory([
            async () => ({ decision: 0x00, sanitisedPayload: Buffer.alloc(0) }),
            async () => ({ decision: 0x01, sanitisedPayload: Buffer.from("cleaned") }),
            async () => ({ decision: 0x02, sanitisedPayload: Buffer.alloc(0) }),
        ])
        const fw = new Firewall(
            undefined,
            Buffer.from("0011223344556677", "hex"),
            factory,
        )
        const result = await fw.onContext(["a", "b", "c"])

        assert.strictEqual(result.length, 3)
        assert.strictEqual(result[0].decision, Decision.ALLOW)
        assert.strictEqual(result[0].sanitisedText, null)
        assert.strictEqual(result[1].decision, Decision.SANITISE)
        assert.strictEqual(result[1].sanitisedText, "cleaned")
        assert.strictEqual(result[2].decision, Decision.BLOCK)
        assert.strictEqual(result[2].sanitisedText, null)
    })

    it("sends on_context payload with rag provenance per chunk", async () => {
        const { capture, factory } = makeFactory([
            async () => ({ decision: 0x00, sanitisedPayload: Buffer.alloc(0) }),
            async () => ({ decision: 0x00, sanitisedPayload: Buffer.alloc(0) }),
        ])
        const fw = new Firewall(
            undefined,
            Buffer.from("0011223344556677", "hex"),
            factory,
        )

        await fw.onContext(["chunk one", "chunk two"])

        assert.strictEqual(capture.transport.seenPayloads.length, 2)
        const first = JSON.parse(capture.transport.seenPayloads[0].toString("utf-8"))
        const second = JSON.parse(capture.transport.seenPayloads[1].toString("utf-8"))
        assert.strictEqual(first.hook_type, "on_context")
        assert.strictEqual(first.provenance, "rag")
        assert.strictEqual(first.payload, "chunk one")
        assert.strictEqual(second.payload, "chunk two")
    })
})

describe("Firewall error propagation and validation", () => {
    it("propagates FirewallConnectionError from transport", async () => {
        const { factory } = makeFactory([
            async () => { throw new FirewallConnectionError("down") },
        ])
        const fw = new Firewall(
            undefined,
            Buffer.from("0011223344556677", "hex"),
            factory,
        )
        await assert.rejects(() => fw.onPrompt("x"), FirewallConnectionError)
    })

    it("propagates FirewallError from transport", async () => {
        const { factory } = makeFactory([
            async () => { throw new FirewallError("bad") },
        ])
        const fw = new Firewall(
            undefined,
            Buffer.from("0011223344556677", "hex"),
            factory,
        )
        await assert.rejects(() => fw.onPrompt("x"), FirewallError)
    })

    it("throws on unknown decision byte", async () => {
        const { factory } = makeFactory([
            async () => ({ decision: 0xFF, sanitisedPayload: Buffer.alloc(0) }),
        ])
        const fw = new Firewall(
            undefined,
            Buffer.from("0011223344556677", "hex"),
            factory,
        )
        await assert.rejects(() => fw.onPrompt("x"), RangeError)
    })

    it("validates onContext argument type", async () => {
        const { factory } = makeFactory([])
        const fw = new Firewall(
            undefined,
            Buffer.from("0011223344556677", "hex"),
            factory,
        )
        await assert.rejects(
            () => fw.onContext("bad" as unknown as string[]),
            FirewallError,
        )
    })

    it("validates onToolCall params type", async () => {
        const { factory } = makeFactory([])
        const fw = new Firewall(
            undefined,
            Buffer.from("0011223344556677", "hex"),
            factory,
        )
        await assert.rejects(
            () => fw.onToolCall("search", null as unknown as Record<string, unknown>),
            FirewallError,
        )
    })

    it("validates onMemory key/value types", async () => {
        const { factory } = makeFactory([])
        const fw = new Firewall(
            undefined,
            Buffer.from("0011223344556677", "hex"),
            factory,
        )
        await assert.rejects(
            () => fw.onMemory(123 as unknown as string, "x"),
            FirewallError,
        )
    })
})

describe("Firewall edge cases", () => {
    it("supports unicode text payload", async () => {
        const { capture, factory } = makeFactory([
            async () => ({ decision: 0x00, sanitisedPayload: Buffer.alloc(0) }),
        ])
        const fw = new Firewall(
            undefined,
            Buffer.from("0011223344556677", "hex"),
            factory,
        )

        await fw.onPrompt("こんにちは世界")
        const payload = JSON.parse(capture.transport.seenPayloads[0].toString("utf-8"))
        assert.strictEqual(payload.payload, "こんにちは世界")
    })

    it("multiple sequential calls are independent", async () => {
        const { capture, factory } = makeFactory([
            async () => ({ decision: 0x00, sanitisedPayload: Buffer.alloc(0) }),
            async () => ({ decision: 0x02, sanitisedPayload: Buffer.alloc(0) }),
        ])
        const fw = new Firewall(
            undefined,
            Buffer.from("0011223344556677", "hex"),
            factory,
        )

        const r1 = await fw.onPrompt("first")
        const r2 = await fw.onPrompt("second")
        assert.strictEqual(r1, Decision.ALLOW)
        assert.strictEqual(r2, Decision.BLOCK)
        assert.strictEqual(capture.transport.seenPayloads.length, 2)
    })

    it("does not mutate input params object", async () => {
        const { factory } = makeFactory([
            async () => ({ decision: 0x00, sanitisedPayload: Buffer.alloc(0) }),
        ])
        const fw = new Firewall(
            undefined,
            Buffer.from("0011223344556677", "hex"),
            factory,
        )

        const params = { q: "test" }
        const before = JSON.stringify(params)
        await fw.onToolCall("search", params)
        assert.strictEqual(JSON.stringify(params), before)
    })
})
