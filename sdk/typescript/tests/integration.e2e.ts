/// <reference types="node" />

import { describe, it } from "node:test"
import assert from "node:assert/strict"

import { Firewall } from "../src/firewall.js"
import { Decision, FirewallConnectionError, FirewallError } from "../src/models.js"
import {
    ensureSidecarBinary,
    findRepoRoot,
    isSocketBindPermissionError,
    makeSocketPath,
    normalizeDecision,
    startSidecar,
    stopSidecar,
    waitForSidecarReady,
} from "./e2e_helpers.js"

describe("TypeScript SDK integration with live sidecar", () => {
    it("round-trips all v1 hooks against a real sidecar process", async (t) => {
        const repoRoot = findRepoRoot()
        const ready = ensureSidecarBinary(repoRoot)
        if (!ready.ok) {
            t.skip(ready.reason)
            return
        }

        const keyHex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
        const socketPath = makeSocketPath("hooks")
        const sidecar = startSidecar({ repoRoot, keyHex, socketPath })

        try {
            try {
                await waitForSidecarReady({ socketPath, keyHex, sidecar })
            } catch (err) {
                if (isSocketBindPermissionError(err)) {
                    t.skip(`sidecar socket bind is not permitted in this environment: ${String((err as Error).message)}`)
                    return
                }
                throw err
            }
            const fw = new Firewall(socketPath, Buffer.from(keyHex, "hex"))

            const prompt = await fw.onPrompt("hello world")
            assert.strictEqual(normalizeDecision(prompt), "ALLOW")

            const context = await fw.onContext(["chunk one", "chunk two"])
            assert.strictEqual(context.length, 2)
            assert.strictEqual(context[0]?.decision, Decision.ALLOW)
            assert.strictEqual(context[1]?.decision, Decision.ALLOW)

            const tool = await fw.onToolCall("search", { q: "weather" })
            assert.strictEqual(normalizeDecision(tool), "ALLOW")

            const memory = await fw.onMemory("pref", "dark", "write")
            assert.strictEqual(normalizeDecision(memory), "ALLOW")
        } finally {
            await stopSidecar(sidecar)
        }
    })

    it("fails closed when sidecar is running with a different key", async (t) => {
        const repoRoot = findRepoRoot()
        const ready = ensureSidecarBinary(repoRoot)
        if (!ready.ok) {
            t.skip(ready.reason)
            return
        }

        const keyHex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        const wrongKeyHex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        const socketPath = makeSocketPath("wrong-key")
        const sidecar = startSidecar({ repoRoot, keyHex, socketPath })

        try {
            try {
                await waitForSidecarReady({ socketPath, keyHex, sidecar })
            } catch (err) {
                if (isSocketBindPermissionError(err)) {
                    t.skip(`sidecar socket bind is not permitted in this environment: ${String((err as Error).message)}`)
                    return
                }
                throw err
            }
            const fwWrong = new Firewall(socketPath, Buffer.from(wrongKeyHex, "hex"))
            await assert.rejects(
                () => fwWrong.onPrompt("hello"),
                FirewallError,
            )
        } finally {
            await stopSidecar(sidecar)
        }
    })

    it("returns FirewallConnectionError when sidecar is unavailable", async () => {
        const keyHex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
        const fw = new Firewall(makeSocketPath("missing"), Buffer.from(keyHex, "hex"))
        await assert.rejects(() => fw.onPrompt("hello"), FirewallConnectionError)
    })
})
