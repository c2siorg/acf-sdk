"""Tests for acf.transport — UDS client using a mock socket."""
from __future__ import annotations

import hashlib
import hmac
import math
import os
import socket
import struct
import threading
import time
from unittest.mock import MagicMock, patch

import pytest
from acf.frame import HEADER_SIZE, signed_message, encode_response
from acf.models import FirewallConnectionError, FirewallError, FirewallTimeout
from acf.transport import Transport, MAX_ATTEMPTS, DEFAULT_TIMEOUT, _resolve_timeout

KEY          = b"test-key-32-bytes-long-padded!!!"
ALLOW_RESP   = encode_response(0x00)
BLOCK_RESP   = encode_response(0x02)
SANITISE_BODY = b"safe content"
SANITISE_RESP = encode_response(0x01, SANITISE_BODY)

requires_uds = pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"),
    reason="AF_UNIX unavailable on this platform",
)


@pytest.fixture(autouse=True)
def _no_ambient_timeout_env(monkeypatch):
    """ACF_TIMEOUT_MS must not leak in from the developer's shell."""
    monkeypatch.delenv("ACF_TIMEOUT_MS", raising=False)


def _make_transport(**kw) -> Transport:
    return Transport(socket_path="/tmp/acf_test.sock", key=KEY, **kw)


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


# ── timeout: configuration ────────────────────────────────────────────────────

def test_default_timeout_is_a_positive_finite_ceiling():
    assert isinstance(DEFAULT_TIMEOUT, float)
    assert DEFAULT_TIMEOUT > 0
    assert math.isfinite(DEFAULT_TIMEOUT)


def test_default_is_used_when_nothing_is_configured():
    assert _make_transport().timeout == DEFAULT_TIMEOUT
    assert _resolve_timeout() == DEFAULT_TIMEOUT


def test_explicit_timeout_wins(monkeypatch):
    monkeypatch.setenv("ACF_TIMEOUT_MS", "9000")
    assert _make_transport(timeout=0.75).timeout == 0.75


def test_env_var_is_read_when_no_explicit_value(monkeypatch):
    monkeypatch.setenv("ACF_TIMEOUT_MS", "250")
    assert _make_transport().timeout == 0.25
    assert _resolve_timeout() == 0.25


@pytest.mark.parametrize("ms", ["0", "-1", "nan", "inf", "-inf"])
def test_non_positive_and_non_finite_env_disables_the_ceiling(monkeypatch, ms):
    monkeypatch.setenv("ACF_TIMEOUT_MS", ms)
    assert _resolve_timeout() is None
    assert _make_transport().timeout is None


def test_unparseable_env_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("ACF_TIMEOUT_MS", "soon")
    assert _resolve_timeout() == DEFAULT_TIMEOUT


@pytest.mark.parametrize("bad", [0, 0.0, -1, -0.5, float("nan"), float("inf")])
def test_bad_explicit_timeout_never_reaches_settimeout(bad):
    """settimeout(0) means non-blocking, and nan/inf raise inside the socket layer."""
    resolved = _make_transport(timeout=bad).timeout
    assert resolved is None, f"{bad!r} must not survive as a socket timeout"


def test_positional_construction_still_works():
    """Firewall builds Transport by keyword; the historical positional form must hold."""
    t = Transport("/tmp/acf.sock", KEY)
    assert t.socket_path == "/tmp/acf.sock"
    assert t.key == KEY
    assert t.timeout == DEFAULT_TIMEOUT


# ── timeout: enforcement ──────────────────────────────────────────────────────

def test_uds_socket_receives_the_configured_timeout():
    """The whole socket module is stubbed so this runs on Windows too."""
    sock = MagicMock()
    sock.__enter__.return_value = sock
    sock.__exit__.return_value = False
    sock.recv.side_effect = [ALLOW_RESP[:5]]

    fake = MagicMock()
    fake.AF_UNIX = "AF_UNIX"
    fake.SOCK_STREAM = "SOCK_STREAM"
    fake.socket.return_value = sock

    with patch("acf.transport.socket", fake):
        with patch("acf.transport._IS_WINDOWS", False):
            _make_transport(timeout=1.25).send(b"{}")

    sock.settimeout.assert_called_once_with(1.25)
    sock.connect.assert_called_once_with("/tmp/acf_test.sock")
    sock.sendall.assert_called_once()


def test_socket_timeout_is_translated_to_firewall_timeout():
    """A raw socket timeout must surface as a FirewallError subclass, not bare TimeoutError."""
    t = _make_transport(timeout=0.5)
    with patch.object(t, "_connect_and_send", side_effect=TimeoutError("timed out")):
        with pytest.raises(FirewallTimeout):
            t.send(b"{}")


def test_firewall_timeout_stays_inside_the_error_hierarchy():
    """adapters/agent_kernel.py catches FirewallError to fail closed; keep it working."""
    assert issubclass(FirewallTimeout, FirewallConnectionError)
    assert issubclass(FirewallTimeout, Exception)
    with pytest.raises(FirewallError):
        raise FirewallTimeout("x")


def test_timeout_is_not_retried():
    """Retrying a wedged sidecar multiplies the budget rather than recovering."""
    t = _make_transport(timeout=0.5)
    attempts = 0

    def side_effect(_frame):
        nonlocal attempts
        attempts += 1
        raise TimeoutError("timed out")

    with patch.object(t, "_connect_and_send", side_effect=side_effect):
        with pytest.raises(FirewallTimeout):
            t.send(b"{}")

    assert attempts == 1


def test_connection_refused_is_still_retried_not_treated_as_timeout():
    """The new except clause must not swallow the existing retry behaviour."""
    t = _make_transport(timeout=0.5)
    attempts = 0

    def side_effect(_frame):
        nonlocal attempts
        attempts += 1
        raise ConnectionRefusedError("down")

    with patch.object(t, "_connect_and_send", side_effect=side_effect):
        with patch("acf.transport.time.sleep"):
            with pytest.raises(FirewallConnectionError):
                t.send(b"{}")

    assert attempts == MAX_ATTEMPTS


@requires_uds
def test_real_stalled_sidecar_does_not_block_past_the_timeout(tmp_path):
    """End-to-end: a listener that accepts and never replies must not hang the caller."""
    path = str(tmp_path / "acf.sock")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(path)
    listener.listen(1)

    def accept_then_stall():
        try:
            conn, _ = listener.accept()
            time.sleep(10)
            conn.close()
        except OSError:
            pass

    threading.Thread(target=accept_then_stall, daemon=True).start()

    try:
        transport = Transport(socket_path=path, key=KEY, timeout=0.5)
        started = time.monotonic()
        with pytest.raises(FirewallTimeout):
            transport.send(b"{}")
        elapsed = time.monotonic() - started
        assert elapsed < 5.0, f"send() blocked for {elapsed:.1f}s - ceiling not enforced"
    finally:
        listener.close()
