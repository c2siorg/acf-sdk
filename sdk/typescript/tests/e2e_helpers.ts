import { spawn, spawnSync, type ChildProcess } from "node:child_process"
import { existsSync } from "node:fs"
import path from "node:path"
import os from "node:os"

import { Decision, type SanitiseResult } from "../src/models.js"
import { Firewall } from "../src/firewall.js"

type SidecarHandle = {
    proc: ChildProcess
    logs: string[]
}

function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms))
}

export function findRepoRoot(): string {
    let cursor = process.cwd()
    for (let i = 0; i < 10; i += 1) {
        if (
            existsSync(path.join(cursor, "sidecar")) &&
            existsSync(path.join(cursor, "sdk"))
        ) {
            return cursor
        }
        const parent = path.dirname(cursor)
        if (parent === cursor) {
            break
        }
        cursor = parent
    }
    throw new Error(`Could not locate repo root from ${cursor}`)
}

export function sidecarBinaryPath(repoRoot: string): string {
    const exe = process.platform === "win32" ? "acf-sidecar.exe" : "acf-sidecar"
    return process.env.ACF_SIDECAR_BIN || path.join(repoRoot, "bin", exe)
}

export function makeSocketPath(label: string): string {
    if (process.platform === "win32") {
        return `\\\\.\\pipe\\acf_ts_${label}_${process.pid}_${Date.now()}`
    }
    return path.join(
        os.tmpdir(),
        `acf_ts_${label}_${process.pid}_${Date.now()}.sock`,
    )
}

export function ensureSidecarBinary(repoRoot: string): { ok: true } | { ok: false; reason: string } {
    const binPath = sidecarBinaryPath(repoRoot)
    if (existsSync(binPath)) {
        return { ok: true }
    }

    const build = spawnSync(
        "go",
        ["build", "-o", binPath, "./cmd/sidecar"],
        {
            cwd: path.join(repoRoot, "sidecar"),
            env: {
                ...process.env,
                GOCACHE: process.env.GOCACHE || path.join(os.tmpdir(), "acf-go-build-cache"),
            },
            encoding: "utf-8",
        },
    )

    if (build.status !== 0 || !existsSync(binPath)) {
        return {
            ok: false,
            reason: `unable to build sidecar binary at ${binPath}: ${build.stderr || build.stdout || "unknown build error"}`,
        }
    }
    return { ok: true }
}

export function hasPython3(): boolean {
    const out = spawnSync("python3", ["--version"], { encoding: "utf-8" })
    return out.status === 0
}

export function startSidecar(params: {
    repoRoot: string
    keyHex: string
    socketPath: string
}): SidecarHandle {
    const binPath = sidecarBinaryPath(params.repoRoot)
    const logs: string[] = []
    const proc = spawn(
        binPath,
        [],
        {
            env: {
                ...process.env,
                ACF_HMAC_KEY: params.keyHex,
                ACF_SOCKET_PATH: params.socketPath,
            },
            stdio: ["ignore", "pipe", "pipe"],
        },
    )

    proc.stdout.on("data", (d) => logs.push(String(d)))
    proc.stderr.on("data", (d) => logs.push(String(d)))
    return { proc, logs }
}

export async function stopSidecar(handle: SidecarHandle): Promise<void> {
    const { proc } = handle
    if (proc.exitCode !== null) {
        return
    }

    const closed = new Promise<void>((resolve) => {
        proc.once("close", () => resolve())
    })
    proc.kill("SIGTERM")

    const timeout = sleep(1500).then(() => {
        if (proc.exitCode === null) {
            proc.kill("SIGKILL")
        }
    })
    await Promise.race([closed, timeout])
    await closed
}

export async function waitForSidecarReady(params: {
    socketPath: string
    keyHex: string
    sidecar: SidecarHandle
    timeoutMs?: number
}): Promise<void> {
    const timeoutMs = params.timeoutMs ?? 5000
    const fw = new Firewall(params.socketPath, Buffer.from(params.keyHex, "hex"))
    const deadline = Date.now() + timeoutMs

    while (Date.now() < deadline) {
        if (params.sidecar.proc.exitCode !== null) {
            throw new Error(
                `sidecar exited early with code ${params.sidecar.proc.exitCode}: ${params.sidecar.logs.join("")}`,
            )
        }
        try {
            await fw.onPrompt("acf-ready-check")
            return
        } catch {
            await sleep(50)
        }
    }
    throw new Error(`sidecar readiness timeout after ${timeoutMs}ms: ${params.sidecar.logs.join("")}`)
}

export function isSocketBindPermissionError(err: unknown): boolean {
    if (!(err instanceof Error)) {
        return false
    }
    const msg = err.message.toLowerCase()
    return (
        msg.includes("bind: operation not permitted") ||
        msg.includes("failed to create listener") ||
        msg.includes("listen unix")
    )
}

export function normalizeDecision(
    result: Decision | SanitiseResult,
): "ALLOW" | "SANITISE" | "BLOCK" {
    if (typeof result === "object") {
        return "SANITISE"
    }
    if (result === Decision.ALLOW) {
        return "ALLOW"
    }
    if (result === Decision.BLOCK) {
        return "BLOCK"
    }
    return "SANITISE"
}
