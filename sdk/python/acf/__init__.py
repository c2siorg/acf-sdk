"""
ACF SDK — Agentic Cognitive Firewall.

Public API:
    Firewall       — main entry point, four hook call sites
    Decision       — ALLOW | SANITISE | BLOCK
    SanitiseResult — returned on SANITISE, contains the scrubbed payload
    ChunkResult    — per-chunk result from on_context
    FirewallError  — base exception
    FirewallConnectionError — raised when the sidecar is unreachable
"""
from .firewall import Firewall
from .models import (
    ChunkResult,
    Decision,
    FirewallConnectionError,
    FirewallError,
    SanitiseResult,
)

__all__ = [
    "Firewall",
    "Decision",
    "SanitiseResult",
    "ChunkResult",
    "FirewallError",
    "FirewallConnectionError",
]
