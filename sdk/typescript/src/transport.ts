import * as net from 'net';
import * as os from 'os';
import { encodeRequest, decodeResponse, FrameError } from './frame';
import { FirewallConnectionError } from './models';

const IS_WINDOWS = os.platform() === 'win32';
export const DEFAULT_SOCKET_PATH = IS_WINDOWS ? '\\\\.\\pipe\\acf' : '/tmp/acf.sock';
const MAX_ATTEMPTS = 3;
const BACKOFF_BASE_MS = 100;

export class Transport {
  public socketPath: string;
  public key: Buffer;

  constructor(socketPath: string = DEFAULT_SOCKET_PATH, key: Buffer = Buffer.alloc(0)) {
    this.socketPath = socketPath;
    this.key = key;
  }

  public async send(payload: Buffer): Promise<{ decision: number; sanitisedPayload: Buffer }> {
    const frame = encodeRequest(payload, this.key);
    let delay = BACKOFF_BASE_MS;
    let lastErr: Error | null = null;

    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
      try {
        const raw = await this.connectAndSend(frame);
        return decodeResponse(raw);
      } catch (err: any) {
        lastErr = err;
        // Retry on connection refused or not found
        if (err.code === 'ECONNREFUSED' || err.code === 'ENOENT') {
          if (attempt < MAX_ATTEMPTS) {
            await new Promise((resolve) => setTimeout(resolve, delay));
            delay *= 2;
            continue;
          }
          break;
        }
        // Re-raise any other errors immediately
        throw err;
      }
    }

    throw new FirewallConnectionError(
      `Could not connect to sidecar at ${this.socketPath} after ${MAX_ATTEMPTS} attempts: ${lastErr?.message}`
    );
  }

  private connectAndSend(frameBytes: Buffer): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const client = net.createConnection(this.socketPath);
      let responseData = Buffer.alloc(0);
      let expectedSanLen: number | null = null;
      let headerRead = false;

      client.on('connect', () => {
        client.write(frameBytes);
      });

      client.on('data', (chunk: Buffer) => {
        responseData = Buffer.concat([responseData, chunk]);
        
        if (!headerRead && responseData.length >= 5) {
          expectedSanLen = responseData.readUInt32BE(1);
          headerRead = true;
        }

        if (headerRead && expectedSanLen !== null) {
          const expectedTotalLen = 5 + expectedSanLen;
          if (responseData.length >= expectedTotalLen) {
            client.end();
            resolve(responseData.subarray(0, expectedTotalLen));
          }
        }
      });

      client.on('error', (err) => {
        reject(err);
      });

      client.on('end', () => {
        if (!headerRead || (expectedSanLen !== null && responseData.length < 5 + expectedSanLen)) {
          reject(new FrameError('connection closed before full response received'));
        }
      });
    });
  }
}
