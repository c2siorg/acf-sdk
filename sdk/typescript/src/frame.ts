import * as crypto from 'crypto';

export const MAGIC = 0xAC;
export const VERSION = 1;
export const HEADER_SIZE = 54; // 1 + 1 + 4 + 16 + 32

export class FrameError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'FrameError';
  }
}

/**
 * Encode a signed request frame.
 * Layout:
 *   [0]      magic     — 0xAC
 *   [1]      version   — 1
 *   [2:6]    length    — uint32 big-endian
 *   [6:22]   nonce     — 16 random bytes
 *   [22:54]  hmac      — 32 bytes HMAC-SHA256 over signed_message
 *   [54:]    payload   — JSON bytes
 */
export function encodeRequest(payload: Buffer, key: Buffer): Buffer {
  const nonce = crypto.randomBytes(16);
  const length = payload.length;

  // signed_message layout: version(1B) || length(4B BE) || nonce(16B) || payload
  const prefix = Buffer.alloc(21);
  prefix.writeUInt8(VERSION, 0);
  prefix.writeUInt32BE(length, 1);
  nonce.copy(prefix, 5);
  
  const msg = Buffer.concat([prefix, payload]);
  const hmac = crypto.createHmac('sha256', key).update(msg).digest();

  const header = Buffer.alloc(HEADER_SIZE);
  header.writeUInt8(MAGIC, 0);
  header.writeUInt8(VERSION, 1);
  header.writeUInt32BE(length, 2);
  nonce.copy(header, 6);
  hmac.copy(header, 22);

  return Buffer.concat([header, payload]);
}

/**
 * Decode a response frame from raw bytes.
 * Layout:
 *   [0]      decision  — 0x00 ALLOW | 0x01 SANITISE | 0x02 BLOCK
 *   [1:5]    san_len   — uint32 big-endian (0 if not SANITISE)
 *   [5:]     sanitised — JSON bytes (SANITISE only)
 */
export function decodeResponse(data: Buffer): { decision: number; sanitisedPayload: Buffer } {
  if (data.length < 5) {
    throw new FrameError(`truncated response: got ${data.length} bytes, need at least 5`);
  }
  const decision = data.readUInt8(0);
  const sanLen = data.readUInt32BE(1);
  
  if (data.length < 5 + sanLen) {
    throw new FrameError(`truncated response payload: got ${data.length - 5} bytes, want ${sanLen}`);
  }
  
  const sanitisedPayload = sanLen > 0 ? data.subarray(5, 5 + sanLen) : Buffer.alloc(0);
  
  return { decision, sanitisedPayload };
}
