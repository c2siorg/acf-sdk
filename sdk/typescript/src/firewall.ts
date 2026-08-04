import { Transport, DEFAULT_SOCKET_PATH } from './transport';
import { Decision, SanitiseResult, ChunkResult, FirewallError, RiskContext } from './models';

export class Firewall {
  private transport: Transport;

  constructor(socketPath?: string, hmacKey?: Buffer) {
    const resolvedPath = socketPath || process.env.ACF_SOCKET_PATH || DEFAULT_SOCKET_PATH;

    let key = hmacKey;
    if (!key) {
      const raw = process.env.ACF_HMAC_KEY || '';
      if (!raw) {
        throw new FirewallError('No HMAC key provided. Pass hmacKey= or set ACF_HMAC_KEY (hex-encoded, min 32 bytes).');
      }
      try {
        key = Buffer.from(raw, 'hex');
      } catch (err) {
        throw new FirewallError(`ACF_HMAC_KEY is not valid hex: ${err}`);
      }
    }

    this.transport = new Transport(resolvedPath, key);
  }

  public async onPrompt(text: string): Promise<Decision | SanitiseResult> {
    const payload = this.buildPayload('on_prompt', text, 'user');
    return this.send(payload);
  }

  public async onContext(chunks: string[]): Promise<ChunkResult[]> {
    const results: ChunkResult[] = [];
    for (const chunk of chunks) {
      const payload = this.buildPayload('on_context', chunk, 'rag');
      const decision = await this.send(payload);
      
      if (typeof decision === 'object' && decision.decision === Decision.SANITISE) {
        results.push({
          original: chunk,
          decision: Decision.SANITISE,
          sanitisedText: decision.sanitisedText
        });
      } else {
        results.push({
          original: chunk,
          decision: decision as Decision,
          sanitisedText: null
        });
      }
    }
    return results;
  }

  public async onToolCall(name: string, params: any): Promise<Decision | SanitiseResult> {
    const payload = this.buildPayload('on_tool_call', { name, params }, 'agent');
    return this.send(payload);
  }

  public async onMemory(key: string, value: string, op: 'write' | 'read' = 'write'): Promise<Decision | SanitiseResult> {
    const payload = this.buildPayload('on_memory', { key, value, op }, 'agent');
    return this.send(payload);
  }

  private buildPayload(
    hookType: string,
    content: any,
    provenance: string = 'sdk',
    sessionId: string = ''
  ): Buffer {
    const ctx: RiskContext = {
      score: 0.0,
      signals: [], // Semantic scanner omitted for V1
      provenance,
      session_id: sessionId,
      hook_type: hookType,
      payload: content,
      state: null
    };
    return Buffer.from(JSON.stringify(ctx), 'utf-8');
  }

  private async send(payload: Buffer): Promise<Decision | SanitiseResult> {
    const resp = await this.transport.send(payload);
    const decision = resp.decision;

    if (decision === Decision.SANITISE) {
      const raw = resp.sanitisedPayload;
      const text = raw.length > 0 ? raw.toString('utf-8') : null;
      return {
        decision: Decision.SANITISE,
        sanitisedPayload: raw,
        sanitisedText: text
      };
    }
    
    if (decision === Decision.ALLOW) return Decision.ALLOW;
    if (decision === Decision.BLOCK) return Decision.BLOCK;
    
    throw new FirewallError(`Unknown decision byte: ${decision}`);
  }
}
