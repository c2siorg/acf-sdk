"""Tests for acf.transport — UDS client using a mock socket."""
from __future__ import annotations

import hashlib
import hmac
import struct
import unittest
from unittest.mock import MagicMock, patch, call

import pytest
from acf.frame import HEADER_SIZE, signed_message, encode_response
from acf.models import FirewallConnectionError
from acf.transport import Transport, MAX_ATTEMPTS

KEY          = b"test-key-32-bytes-long-padded!!!"
ALLOW_RESP   = encode_response(0x00)
BLOCK_RESP   = encode_response(0x02)
SANITISE_BODY = b"safe content"
SANITISE_RESP = encode_response(0x01, SANITISE_BODY)


def _make_transport() -> Transport:
    return Transport(socket_path="/tmp/acf_test.sock", key=KEY)


def _mock_socket(response_bytes: bytes):
    """Return a mock socket whose recv yields *response_bytes* in one chunk."""
    mock_sock = MagicMock()
    # Simulate header (5 bytes) then body separately for _recv_exact calls.
    header = response_bytes[:5]
    san_len = struct.unpack(">I", header[1:5])[0]
    body = response_bytes[5:5 + san_len]

    mock_sock.recv.side_effect = [header, body] if san_len > 0 else [header]
    return mock_sock


# ── happy-path responses ──────────────────────────────────────────────────────

def test_send_allow_response():
    t = _make_transport()
    with patch.object(t, "_connect_and_send", return_value=ALLOW_RESP):
        result = t.send(b'{"hook_type":"on_prompt"}')

    assert result["decision"] == 0x00
    assert result["sanitised_payload"] == b""


def test_send_block_response():
    t = _make_transport()
    with patch.object(t, "_connect_and_send", return_value=BLOCK_RESP):
        result = t.send(b'{"hook_type":"on_prompt"}')

    assert result["decision"] == 0x02


def test_send_sanitise_response():
    t = _make_transport()
    with patch.object(t, "_connect_and_send", return_value=SANITISE_RESP):
        result = t.send(b'{"hook_type":"on_prompt"}')

    assert result["decision"] == 0x01
    assert result["sanitised_payload"] == SANITISE_BODY


# ── retry logic ───────────────────────────────────────────────────────────────

def test_retry_on_connection_refused():
    """Transient ConnectionRefusedError retries, then succeeds."""
    t = _make_transport()
    attempt_count = 0

    def side_effect(frame_bytes):
        nonlocal attempt_count
        attempt_count += 1
        if attempt_count < 3:
            raise ConnectionRefusedError("not ready yet")
        # Third attempt: return a real socket that returns ALLOW.
        sock = _mock_socket(ALLOW_RESP)
        sock.connect.return_value = None
        sock.sendall.return_value = None
        return ALLOW_RESP

    with patch.object(t, "_connect_and_send", side_effect=side_effect):
        with patch("acf.transport.time.sleep"):  # don't actually sleep in tests
            result = t.send(b"{}")

    assert attempt_count == 3
    assert result["decision"] == 0x00


def test_retry_exhausted():
    """After MAX_ATTEMPTS failures, FirewallConnectionError is raised."""
    t = _make_transport()

    with patch.object(t, "_connect_and_send", side_effect=ConnectionRefusedError("down")):
        with patch("acf.transport.time.sleep"):
            with pytest.raises(FirewallConnectionError):
                t.send(b"{}")


def test_non_transient_error_not_retried():
    """PermissionError is not a transient connection error — must not retry."""
    t = _make_transport()
    call_count = 0

    def side_effect(_):
        nonlocal call_count
        call_count += 1
        raise PermissionError("permission denied")

    with patch.object(t, "_connect_and_send", side_effect=side_effect):
        with pytest.raises(PermissionError):
            t.send(b"{}")

    assert call_count == 1  # no retries


# ── HMAC is applied correctly ─────────────────────────────────────────────────

def test_hmac_applied():
    """The frame sent on the wire must carry a valid HMAC for the given key."""
    t           = _make_transport()
    sent_frames = []

    def capture_and_return(frame_bytes):
        sent_frames.append(frame_bytes)
        return ALLOW_RESP

    with patch.object(t, "_connect_and_send", side_effect=capture_and_return):
        t.send(b'{"hook_type":"on_prompt"}')

    assert sent_frames, "no frame was sent"
    frame = sent_frames[0]

    version = frame[1]
    length  = struct.unpack(">I", frame[2:6])[0]
    nonce   = frame[6:22]
    mac     = frame[22:54]
    payload = frame[HEADER_SIZE:]

    msg      = signed_message(version, length, nonce, payload)
    expected = hmac.new(KEY, msg, hashlib.sha256).digest()
    assert hmac.compare_digest(mac, expected), "HMAC in sent frame is invalid"
