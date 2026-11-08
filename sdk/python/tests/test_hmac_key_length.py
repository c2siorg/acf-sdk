"""
The HMAC key must be at least 32 bytes, whether it arrives as bytes or as the
ACF_HMAC_KEY hex string. A shorter key is trivially brute forceable, so the
SDK refuses to build a Firewall with one, matching the sidecar and the docs.
"""
from __future__ import annotations

import pytest

from acf import Firewall, MIN_HMAC_KEY_BYTES
from acf.models import FirewallError

SOCKET_PATH = "/tmp/acf_test_hmac_key_length.sock"
GOOD_KEY = b"test-key-32-bytes-long-padded!!!"


@pytest.fixture(autouse=True)
def clear_env(monkeypatch):
    monkeypatch.delenv("ACF_SEMANTIC_SCAN", raising=False)
    monkeypatch.delenv("ACF_HMAC_KEY", raising=False)


def test_minimum_is_32_bytes():
    assert MIN_HMAC_KEY_BYTES == 32


@pytest.mark.parametrize("key", [b"a", b"\x00", b"12345678", b"x" * 31])
def test_short_key_is_rejected(key):
    with pytest.raises(FirewallError) as excinfo:
        Firewall(socket_path=SOCKET_PATH, hmac_key=key)
    assert "at least 32" in str(excinfo.value)


def test_short_key_from_env_is_rejected(monkeypatch):
    monkeypatch.setenv("ACF_HMAC_KEY", "ab")
    with pytest.raises(FirewallError) as excinfo:
        Firewall(socket_path=SOCKET_PATH)
    assert "at least 32" in str(excinfo.value)


@pytest.mark.parametrize("key", [GOOD_KEY, b"k" * 32, b"k" * 64])
def test_key_at_or_above_minimum_is_accepted(key):
    fw = Firewall(socket_path=SOCKET_PATH, hmac_key=key)
    assert fw._transport.key == key


def test_key_from_env_at_minimum_is_accepted(monkeypatch):
    raw = (b"k" * 32).hex()
    monkeypatch.setenv("ACF_HMAC_KEY", raw)
    fw = Firewall(socket_path=SOCKET_PATH)
    assert fw._transport.key == b"k" * 32
