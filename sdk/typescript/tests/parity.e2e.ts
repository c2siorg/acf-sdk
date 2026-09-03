/// <reference types="node" />

import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { spawnSync } from "node:child_process"
import path from "node:path"

import { Firewall } from "../src/firewall.js"
import { normalizeDecision } from "./e2e_helpers.js"
import {
    ensureSidecarBinary,
    findRepoRoot,
    hasPython3,
    isSocketBindPermissionError,
    makeSocketPath,
    startSidecar,
    stopSidecar,
    waitForSidecarReady,
} from "./e2e_helpers.js"

type HookScenario =
    | { hook: "on_prompt"; payload: string }
    | { hook: "on_context"; payload: string[] }
    | { hook: "on_tool_call"; payload: { name: string; params: Record<string, unknown> } }
    | { hook: "on_memory"; payload: { key: string; value: string; op: string } }

function runPythonDecision(params: {
    repoRoot: string
    socketPath: string
    keyHex: string
    scenario: HookScenario
}): { ok: true; decision: "ALLOW" | "SANITISE" | "BLOCK" } | { ok: false; reason: string } {
    const script = `
import json,sys
from acf import Firewall, Decision
from acf.models import SanitiseResult

socket_path = sys.argv[1]
key_hex = sys.argv[2]
scenario = json.loads(sys.argv[3])

fw = Firewall(socket_path=socket_path, hmac_key=bytes.fromhex(key_hex))
hook = scenario["hook"]
payload = scenario["payload"]

if hook == "on_prompt":
    result = fw.on_prompt(payload)
elif hook == "on_context":
    rows = fw.on_context(payload)
    rank = {"ALLOW": 0, "SANITISE": 1, "BLOCK": 2}
    worst = "ALLOW"
    for r in rows:
        name = r.decision.name
        if rank[name] > rank[worst]:
            worst = name
    result = worst
elif hook == "on_tool_call":
    result = fw.on_tool_call(payload["name"], payload["params"])
elif hook == "on_memory":
    result = fw.on_memory(payload["key"], payload["value"], payload["op"])
else:
    raise ValueError("unknown hook")

if isinstance(result, str):
    print(json.dumps({"decision": result}))
elif isinstance(result, SanitiseResult):
    print(json.dumps({"decision": "SANITISE"}))
elif isinstance(result, Decision):
    print(json.dumps({"decision": result.name}))
else:
    raise ValueError("unknown response type")
`

    const out = spawnSync(
        "python3",
        ["-c", script, params.socketPath, params.keyHex, JSON.stringify(params.scenario)],
        {
            cwd: params.repoRoot,
            env: {
                ...process.env,
                PYTHONPATH: path.join(params.repoRoot, "sdk", "python"),
                ACF_HMAC_KEY: params.keyHex,
                ACF_SOCKET_PATH: params.socketPath,
            },
            encoding: "utf-8",
        },
    )

    if (out.status !== 0) {
        return { ok: false, reason: out.stderr || out.stdout || "python invocation failed" }
    }

    try {
        const parsed = JSON.parse(out.stdout)
        const decision = parsed.decision as "ALLOW" | "SANITISE" | "BLOCK"
        return { ok: true, decision }
    } catch {
        return { ok: false, reason: `invalid python output: ${out.stdout}` }
    }
}

describe("TypeScript/Python parity against live sidecar", () => {
    it("matches decision category across SDKs for shared scenarios", async (t) => {
        if (!hasPython3()) {
            t.skip("python3 is not available in PATH")
            return
        }

        const repoRoot = findRepoRoot()
        const ready = ensureSidecarBinary(repoRoot)
        if (!ready.ok) {
            t.skip(ready.reason)
            return
        }

        const keyHex = "111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000"
        const socketPath = makeSocketPath("parity")
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

            const scenarios: HookScenario[] = [
                { hook: "on_prompt", payload: "hello from parity" },
                { hook: "on_context", payload: ["doc one", "doc two"] },
                { hook: "on_tool_call", payload: { name: "search", params: { q: "news" } } },
                { hook: "on_memory", payload: { key: "pref", value: "dark", op: "write" } },
            ]

            for (const scenario of scenarios) {
                let tsDecision: "ALLOW" | "SANITISE" | "BLOCK"
                if (scenario.hook === "on_prompt") {
                    tsDecision = normalizeDecision(await fw.onPrompt(scenario.payload))
                } else if (scenario.hook === "on_context") {
                    const rows = await fw.onContext(scenario.payload)
                    if (rows.some((r) => r.decision === 0x02)) {
                        tsDecision = "BLOCK"
                    } else if (rows.some((r) => r.decision === 0x01)) {
                        tsDecision = "SANITISE"
                    } else {
                        tsDecision = "ALLOW"
                    }
                } else if (scenario.hook === "on_tool_call") {
                    tsDecision = normalizeDecision(
                        await fw.onToolCall(scenario.payload.name, scenario.payload.params),
                    )
                } else {
                    tsDecision = normalizeDecision(
                        await fw.onMemory(
                            scenario.payload.key,
                            scenario.payload.value,
                            scenario.payload.op,
                        ),
                    )
                }

                const py = runPythonDecision({
                    repoRoot,
                    socketPath,
                    keyHex,
                    scenario,
                })
                if (!py.ok) {
                    assert.fail(py.reason)
                }
                assert.strictEqual(
                    tsDecision,
                    py.decision,
                    `parity mismatch for ${scenario.hook}`,
                )
            }
        } finally {
            await stopSidecar(sidecar)
        }
    })
})
