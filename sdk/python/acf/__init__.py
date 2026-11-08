"""
ACF SDK — Agentic Cognitive Firewall.

Public API:
    Firewall       — main entry point, four hook call sites
    Session        — hook calls evaluated as one agent session (Firewall.session())
    Decision       — ALLOW | SANITISE | BLOCK
    SanitiseResult — returned on SANITISE, contains the scrubbed payload
    ChunkResult    — per-chunk result from on_context
    FirewallError  — base exception
    FirewallConnectionError — raised when the sidecar is unreachable
    FirewallBlocked — raised by adapters on BLOCK decisions
    MIN_HMAC_KEY_BYTES — minimum accepted HMAC key length (32)
"""
from .firewall import MIN_HMAC_KEY_BYTES, Firewall
from .models import (
    ChunkResult,
    Decision,
    FirewallBlocked,
    FirewallConnectionError,
    FirewallError,
    SanitiseResult,
)
from .session import Session

__all__ = [
    "Firewall",
    "Session",
    "Decision",
    "SanitiseResult",
    "ChunkResult",
    "FirewallBlocked",
    "FirewallError",
    "FirewallConnectionError",
    "MIN_HMAC_KEY_BYTES",
]
