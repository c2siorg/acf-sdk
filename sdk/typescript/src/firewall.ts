/**
 * Firewall class — async/await interface for the four v1 hook call sites.
 *   onPrompt(text: string): Promise<Decision>
 *   onContext(chunks: string[]): Promise<ChunkResult[]>
 *   onToolCall(name: string, params: Record<string, unknown>): Promise<Decision>
 *   onMemory(key: string, value: string, op: string): Promise<Decision>
 */

import {
    ChunkResult,
    Decision,
    FirewallError,
    SanitiseResult,
    decisionFromByte,
} from "./models.js"
import { type ResponseFrame } from "./frame.js"
import { Transport } from "./transport.js"

type HookType = "on_prompt" | "on_context" | "on_tool_call" | "on_memory"
type Provenance = "user" | "rag" | "agent"

interface RiskContext {
    score: number
    signals: string[]
    provenance: Provenance
    session_id: string
    hook_type: HookType
    payload: unknown
    state: null
}

type TransportLike = {
    send(payload: Buffer): Promise<ResponseFrame>
}

type TransportFactory = (socketPath?: string, key?: Buffer) => TransportLike

function resolveKey(inputKey?: Buffer): Buffer {
    if (inputKey) {
        return Buffer.from(inputKey)
    }

    const raw = process.env.ACF_HMAC_KEY || ""
    if (raw.length === 0) {
        throw new FirewallError(
            "No HMAC key provided. Pass hmacKey or set ACF_HMAC_KEY (hex-encoded).",
        )
    }

    if (raw.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(raw)) {
        throw new FirewallError("ACF_HMAC_KEY is not valid hex")
    }

    return Buffer.from(raw, "hex")
}

function isSanitiseResult(
    value: Decision | SanitiseResult,
): value is SanitiseResult {
    return typeof value === "object" && value !== null
}

export class Firewall {
    private readonly transport: TransportLike

    constructor(
        socketPath?: string,
        hmacKey?: Buffer,
        transportFactory: TransportFactory = (path, key) => new Transport(path, key),
    ) {
        const key = resolveKey(hmacKey)
        this.transport = transportFactory(socketPath, key)
    }

    async onPrompt(text: string): Promise<Decision | SanitiseResult> {
        if (typeof text !== "string") {
            throw new FirewallError("onPrompt expects a string payload")
        }
        const payload = this.buildPayload("on_prompt", text, "user")
        return this.send(payload)
    }

    async onContext(chunks: string[]): Promise<ChunkResult[]> {
        if (!Array.isArray(chunks)) {
            throw new FirewallError("onContext expects an array of strings")
        }

        const out: ChunkResult[] = []
        for (const chunk of chunks) {
            if (typeof chunk !== "string") {
                throw new FirewallError("onContext expects an array of strings")
            }
            const payload = this.buildPayload("on_context", chunk, "rag")
            const decision = await this.send(payload)
            if (isSanitiseResult(decision)) {
                out.push({
                    original: chunk,
                    decision: Decision.SANITISE,
                    sanitisedText: decision.sanitisedText,
                })
            } else {
                out.push({
                    original: chunk,
                    decision,
                    sanitisedText: null,
                })
            }
        }
        return out
    }

    async onToolCall(
        name: string,
        params: Record<string, unknown>,
    ): Promise<Decision | SanitiseResult> {
        if (typeof name !== "string") {
            throw new FirewallError("onToolCall expects name to be a string")
        }
        if (!params || typeof params !== "object" || Array.isArray(params)) {
            throw new FirewallError("onToolCall expects params to be an object")
        }
        const payload = this.buildPayload(
            "on_tool_call",
            { name, params },
            "agent",
        )
        return this.send(payload)
    }

    async onMemory(
        key: string,
        value: string,
        op: string = "write",
    ): Promise<Decision | SanitiseResult> {
        if (typeof key !== "string" || typeof value !== "string") {
            throw new FirewallError("onMemory expects key and value to be strings")
        }
        if (typeof op !== "string") {
            throw new FirewallError("onMemory expects op to be a string")
        }
        const payload = this.buildPayload(
            "on_memory",
            { key, value, op },
            "agent",
        )
        return this.send(payload)
    }

    private buildPayload(
        hookType: HookType,
        content: unknown,
        provenance: Provenance,
        sessionId: string = "",
    ): Buffer {
        const ctx: RiskContext = {
            score: 0.0,
            signals: [],
            provenance,
            session_id: sessionId,
            hook_type: hookType,
            payload: content,
            state: null,
        }
        return Buffer.from(JSON.stringify(ctx), "utf-8")
    }

    private async send(payload: Buffer): Promise<Decision | SanitiseResult> {
        const resp = await this.transport.send(payload)
        const decision = decisionFromByte(resp.decision)

        if (decision === Decision.SANITISE) {
            const raw = Buffer.from(resp.sanitisedPayload)
            return {
                decision: Decision.SANITISE,
                sanitisedPayload: raw,
                sanitisedText: raw.length > 0 ? raw.toString("utf-8") : null,
            }
        }
        return decision
    }
}
