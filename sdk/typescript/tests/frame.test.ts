import { test } from 'node:test';
import * as assert from 'node:assert';
import * as crypto from 'crypto';
import { encodeRequest, decodeResponse, MAGIC, VERSION, FrameError } from '../src/frame';

test('encodeRequest correctly formats request frame', () => {
    const payload = Buffer.from('{"test":"payload"}');
    const key = Buffer.alloc(32, 1); // 32 bytes of 0x01
    const frame = encodeRequest(payload, key);
    
    // Header should be exactly 54 bytes
    assert.strictEqual(frame.length, 54 + payload.length);
    assert.strictEqual(frame[0], MAGIC);
    assert.strictEqual(frame[1], VERSION);
    assert.strictEqual(frame.readUInt32BE(2), payload.length);
    
    // Nonce starts at 6 and HMAC starts at 22
    const nonce = frame.subarray(6, 22);
    assert.strictEqual(nonce.length, 16);
    
    // Validate HMAC
    const prefix = Buffer.alloc(21);
    prefix.writeUInt8(VERSION, 0);
    prefix.writeUInt32BE(payload.length, 1);
    nonce.copy(prefix, 5);
    
    const msg = Buffer.concat([prefix, payload]);
    const expectedMac = crypto.createHmac('sha256', key).update(msg).digest();
    
    const actualMac = frame.subarray(22, 54);
    assert.strictEqual(Buffer.compare(actualMac, expectedMac), 0);
    
    // Payload should match
    assert.strictEqual(frame.subarray(54).toString(), '{"test":"payload"}');
});

test('decodeResponse parses ALLOW successfully', () => {
    const buf = Buffer.alloc(5);
    buf.writeUInt8(0, 0); // ALLOW decision
    buf.writeUInt32BE(0, 1); // 0 length
    
    const resp = decodeResponse(buf);
    assert.strictEqual(resp.decision, 0);
    assert.strictEqual(resp.sanitisedPayload.length, 0);
});

test('decodeResponse parses SANITISE successfully', () => {
    const sanText = Buffer.from('sanitized text');
    const buf = Buffer.alloc(5 + sanText.length);
    buf.writeUInt8(1, 0); // SANITISE decision
    buf.writeUInt32BE(sanText.length, 1);
    sanText.copy(buf, 5);
    
    const resp = decodeResponse(buf);
    assert.strictEqual(resp.decision, 1);
    assert.strictEqual(resp.sanitisedPayload.toString(), 'sanitized text');
});

test('decodeResponse throws FrameError on truncated header', () => {
    const buf = Buffer.alloc(3); // Less than 5 bytes
    assert.throws(() => decodeResponse(buf), FrameError);
});

test('decodeResponse throws FrameError on truncated payload', () => {
    const buf = Buffer.alloc(10);
    buf.writeUInt8(1, 0);
    buf.writeUInt32BE(100, 1); // Declares 100 bytes, but only provides 5
    assert.throws(() => decodeResponse(buf), FrameError);
});
