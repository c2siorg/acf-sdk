export enum Decision {
  ALLOW = 0x00,
  SANITISE = 0x01,
  BLOCK = 0x02,
}

export interface SanitiseResult {
  decision: Decision.SANITISE;
  sanitisedPayload: Buffer;
  sanitisedText: string | null;
}

export interface ChunkResult {
  original: string;
  decision: Decision;
  sanitisedText: string | null;
}

export class FirewallError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'FirewallError';
  }
}

export class FirewallConnectionError extends FirewallError {
  constructor(message: string) {
    super(message);
    this.name = 'FirewallConnectionError';
  }
}

export class FirewallBlocked extends FirewallError {
  public hook?: string;
  
  constructor(message: string, hook?: string) {
    super(message);
    this.name = 'FirewallBlocked';
    this.hook = hook;
  }
}

export interface RiskContext {
  score: number;
  signals: any[];
  provenance: string;
  session_id: string;
  hook_type: string;
  payload: any;
  state: any | null;
}
