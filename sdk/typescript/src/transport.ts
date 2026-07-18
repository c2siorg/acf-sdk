/**
 * IPC client transport for the ACF TypeScript SDK.
 *
 * Responsibilities:
 *   - Sign each payload with HMAC-SHA256 + per-request nonce via frame.encodeRequest
 *   - Send one request over one IPC connection
 *   - Read exactly one response frame and decode it
 *   - Retry on transient sidecar availability errors (ECONNREFUSED, ENOENT)
 */

import net from "node:net"

import { decodeResponse, encodeRequest, type ResponseFrame } from "./frame.js"
import { FirewallConnectionError, FirewallError } from "./models.js"

const IS_WINDOWS = process.platform === "win32"

export const DEFAULT_SOCKET_PATH = IS_WINDOWS ? "\\\\.\\pipe\\acf" : "/tmp/acf.sock"
export const MAX_ATTEMPTS = 3
export const BACKOFF_BASE_MS = 100

type NodeErrno = Error & { code?: string }
type Dialer = (path: string) => net.Socket

function isTransientConnectError(err: unknown): err is NodeErrno {
    if (!err || typeof err !== "object") {
        return false
    }
    const code = (err as NodeErrno).code
    return code === "ECONNREFUSED" || code === "ENOENT"
}

function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms))
}

export class Transport {
    readonly socketPath: string
    readonly key: Buffer
    private readonly dialer: Dialer

    constructor(
        socketPath?: string,
        key: Buffer = Buffer.alloc(0),
        dialer: Dialer = (path) => net.createConnection(path),
    ) {
        this.socketPath = socketPath || process.env.ACF_SOCKET_PATH || DEFAULT_SOCKET_PATH
        this.key = key
        this.dialer = dialer
    }

    async send(payload: Buffer): Promise<ResponseFrame> {
        const frame = encodeRequest(payload, this.key)
        let delay = BACKOFF_BASE_MS
        let lastErr: NodeErrno | null = null

        for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt += 1) {
            try {
                const raw = await this.connectAndSend(frame)
                return decodeResponse(raw)
            } catch (err) {
                if (isTransientConnectError(err)) {
                    lastErr = err
                    if (attempt < MAX_ATTEMPTS) {
                        await sleep(delay)
                        delay *= 2
                        continue
                    }
                    break
                }
                throw this.asFirewallError(err, "transport request failed")
            }
        }

        throw new FirewallConnectionError(
            `Could not connect to sidecar at ${this.socketPath} after ${MAX_ATTEMPTS} attempts: ${lastErr?.message ?? "unknown error"}`
        )
    }

    protected async connectAndSend(frame: Buffer): Promise<Buffer> {
        return new Promise<Buffer>((resolve, reject) => {
            const socket = this.dialer(this.socketPath)
            const chunks: Buffer[] = []
            let total = 0
            let expectedLength: number | null = null
            let settled = false

            const fail = (err: unknown): void => {
                if (settled) {
                    return
                }
                settled = true
                socket.destroy()
                reject(err)
            }

            const succeed = (buf: Buffer): void => {
                if (settled) {
                    return
                }
                settled = true
                socket.destroy()
                resolve(buf)
            }

            socket.once("error", (err) => fail(err))

            socket.once("connect", () => {
                socket.write(frame, (err?: Error | null) => {
                    if (err) {
                        fail(err)
                    }
                })
            })

            socket.on("data", (chunk: Buffer) => {
                if (settled) {
                    return
                }

                chunks.push(chunk)
                total += chunk.length

                if (expectedLength === null && total >= 5) {
                    const merged = Buffer.concat(chunks, total)
                    expectedLength = 5 + merged.readUInt32BE(1)
                    chunks.length = 0
                    chunks.push(merged)
                    total = merged.length
                }

                if (expectedLength !== null && total >= expectedLength) {
                    const merged = Buffer.concat(chunks, total)
                    succeed(Buffer.from(merged.subarray(0, expectedLength)))
                }
            })

            socket.once("close", () => {
                if (settled) {
                    return
                }
                fail(
                    new FirewallError(
                        `connection closed before full response was received (got ${total} bytes)`
                    )
                )
            })
        })
    }

    private asFirewallError(err: unknown, context: string): FirewallError {
        if (err instanceof FirewallError) {
            return err
        }
        if (err instanceof Error) {
            return new FirewallError(`${context}: ${err.message}`)
        }
        return new FirewallError(`${context}: ${String(err)}`)
    }
}
