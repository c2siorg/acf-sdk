/// <reference types="node" />
/**
 * tests/models.test.ts
 * ====================
 * Tests for Decision enum, decisionFromByte, and error classes.
 * Zero dependencies — Node built-in test runner only.
 *
 * Run with: node --test tests/models.test.ts
 */
import { describe, it } from "node:test"
import assert from "node:assert/strict"
import {
    Decision,
    decisionFromByte,
    FirewallError,
    FirewallConnectionError,
} from "../src/models.js"

// ── Decision enum values ──────────────────────────────────────────────────────

describe("Decision", () => {

    it("ALLOW has correct wire byte 0x00", () => {
        assert.strictEqual(Decision.ALLOW, 0x00)
    })

    it("SANITISE has correct wire byte 0x01", () => {
        assert.strictEqual(Decision.SANITISE, 0x01)
    })

    it("BLOCK has correct wire byte 0x02", () => {
        assert.strictEqual(Decision.BLOCK, 0x02)
    })

})

// ── decisionFromByte ──────────────────────────────────────────────────────────

describe("decisionFromByte", () => {

    it("0x00 returns Decision.ALLOW", () => {
        assert.strictEqual(decisionFromByte(0x00), Decision.ALLOW)
    })

    it("0x01 returns Decision.SANITISE", () => {
        assert.strictEqual(decisionFromByte(0x01), Decision.SANITISE)
    })

    it("0x02 returns Decision.BLOCK", () => {
        assert.strictEqual(decisionFromByte(0x02), Decision.BLOCK)
    })

    it("unknown byte throws RangeError", () => {
        assert.throws(
            () => decisionFromByte(0xFF),
            RangeError
        )
    })

   it("error message contains the bad byte value", () => {
    assert.throws(
        () => decisionFromByte(0xAB),
        (err: unknown) => {
            assert(err instanceof RangeError)
            assert((err as RangeError).message.includes("ab"))
            return true
        }
    )
})


})

// ── Error hierarchy ───────────────────────────────────────────────────────────

describe("FirewallError", () => {

    it("is an instance of Error", () => {
        const err = new FirewallError("test")
        assert(err instanceof Error)
    })

    it("has correct name property", () => {
        const err = new FirewallError("test")
        assert.strictEqual(err.name, "FirewallError")
    })

    it("preserves message", () => {
        const err = new FirewallError("something went wrong")
        assert.strictEqual(err.message, "something went wrong")
    })

})

describe("FirewallConnectionError", () => {

    it("is an instance of FirewallError", () => {
        const err = new FirewallConnectionError("no socket")
        assert(err instanceof FirewallError)
    })

    it("is an instance of Error", () => {
        const err = new FirewallConnectionError("no socket")
        assert(err instanceof Error)
    })

    it("has correct name property", () => {
        const err = new FirewallConnectionError("no socket")
        assert.strictEqual(err.name, "FirewallConnectionError")
    })

    it("preserves message", () => {
        const err = new FirewallConnectionError("could not connect")
        assert.strictEqual(err.message, "could not connect")
    })

    it("can be caught as FirewallError", () => {
        assert.throws(
            () => { throw new FirewallConnectionError("down") },
            FirewallError
        )
    })

})