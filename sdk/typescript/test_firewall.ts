import { Firewall, Decision } from './src/index';
import * as crypto from 'crypto';

async function run() {
  const keyStr = process.env.ACF_HMAC_KEY || crypto.randomBytes(32).toString('hex');
  const key = Buffer.from(keyStr, 'hex');
  const socketPath = process.env.ACF_SOCKET_PATH || './acf.sock';
  
  const firewall = new Firewall(socketPath, key);

  try {
    const result = await firewall.onPrompt("Hello, world!");
    console.log("SUCCESS! Decision for 'Hello, world!':", result);
  } catch (err) {
    console.error("Failed:", err);
  }
}

run();
