"""
Binary frame encoder/decoder for the ACF IPC protocol.
Mirrors sidecar/internal/transport/frame.go exactly.
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import secrets
import struct

MAGIC       = 0xAC
VERSION     = 1
HEADER_SIZE = 54  # 1 + 1 + 4 + 16 + 32

# Struct format: Big-endian, Magic(B), Version(B), Length(I), Nonce(16s), HMAC(32s)
_HEADER_FMT = ">BB I 16s 32s"
_RESP_FMT   = ">B I"

class FrameError(Exception):
    """Raised on malformed or unrecognised frame data."""

def signed_message(version: int, length: int, nonce: bytes, payload: bytes) -> bytes:
    """Return the byte string that is the HMAC input."""
    return struct.pack(">B I 16s", version, length, nonce) + payload

def encode_request(payload: bytes, key: bytes) -> bytes:
    """Encode a signed request frame (54-byte header + payload)."""
    nonce  = secrets.token_bytes(16)
    length = len(payload)
    msg    = signed_message(VERSION, length, nonce, payload)
    mac    = _hmac.new(key, msg, hashlib.sha256).digest()
    header = struct.pack(_HEADER_FMT, MAGIC, VERSION, length, nonce, mac)
    return header + payload

def decode_response(data: bytes) -> dict:
    """Decode a response frame from the Sidecar."""
    if len(data) < 5:
        raise FrameError(f"truncated response: got {len(data)} bytes, need at least 5")

    decision, san_len = struct.unpack_from(_RESP_FMT, data, 0)
    sanitised = data[5 : 5 + san_len] if san_len > 0 else b""

    return {
        "decision": decision,
        "sanitised_payload": sanitised,
    }