from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from acf import FirewallConnectionError, FirewallError
from api.main import app

client     = TestClient(app)
_PATCH     = "api.main._get_firewall"


# ── Sidecar reachable ─────────────────────────────────────────────────────────

class TestHealthSidecarReachable:

    def test_returns_200(self):
        with patch(_PATCH, return_value=MagicMock()):
            resp = client.get("/health")
        assert resp.status_code == 200

    def test_status_is_ok(self):
        with patch(_PATCH, return_value=MagicMock()):
            resp = client.get("/health")
        assert resp.json()["status"] == "ok"

    def test_sidecar_is_reachable(self):
        with patch(_PATCH, return_value=MagicMock()):
            resp = client.get("/health")
        assert resp.json()["sidecar"] == "reachable"

    def test_response_shape(self):
        """Response must contain exactly status and sidecar fields."""
        with patch(_PATCH, return_value=MagicMock()):
            resp = client.get("/health")
        data = resp.json()
        assert set(data.keys()) == {"status", "sidecar"}


# ── Sidecar unreachable ───────────────────────────────────────────────────────

class TestHealthSidecarUnreachable:

    def test_returns_200_even_when_sidecar_down(self):
        """
        Health must never return non-200.
        API can still serve rule-based decisions without sidecar.
        """
        with patch(_PATCH, side_effect=FirewallConnectionError("no socket")):
            resp = client.get("/health")
        assert resp.status_code == 200

    def test_status_still_ok(self):
        with patch(_PATCH, side_effect=FirewallConnectionError("no socket")):
            resp = client.get("/health")
        assert resp.json()["status"] == "ok"

    def test_sidecar_is_unreachable(self):
        with patch(_PATCH, side_effect=FirewallConnectionError("no socket")):
            resp = client.get("/health")
        assert resp.json()["sidecar"] == "unreachable"


# ── Sidecar misconfigured ─────────────────────────────────────────────────────

class TestHealthSidecarMisconfigured:

    def test_returns_200_when_misconfigured(self):
        with patch(_PATCH, side_effect=FirewallError("no HMAC key")):
            resp = client.get("/health")
        assert resp.status_code == 200

    def test_sidecar_is_misconfigured(self):
        with patch(_PATCH, side_effect=FirewallError("no HMAC key")):
            resp = client.get("/health")
        assert resp.json()["sidecar"] == "misconfigured"


# ── Response contract ─────────────────────────────────────────────────────────

class TestHealthContract:

    @pytest.mark.parametrize("side_effect,expected_sidecar", [
        (None,                                  "reachable"),
        (FirewallConnectionError("no socket"),  "unreachable"),
        (FirewallError("no key"),               "misconfigured"),
    ])
    def test_all_sidecar_states(self, side_effect, expected_sidecar):
        """
        Parametrised contract test — covers all three sidecar states
        in a single test function.
        """
        if side_effect is None:
            with patch(_PATCH, return_value=MagicMock()):
                resp = client.get("/health")
        else:
            with patch(_PATCH, side_effect=side_effect):
                resp = client.get("/health")

        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"
        assert resp.json()["sidecar"] == expected_sidecar