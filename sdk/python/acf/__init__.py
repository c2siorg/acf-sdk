"""
ACF SDK — Agentic Cognitive Firewall.

Public API:
    Firewall       — main entry point, four hook call sites
    Decision       — ALLOW | SANITISE | BLOCK
    SanitiseResult — returned on SANITISE, contains the scrubbed payload
    ChunkResult    — per-chunk result from on_context
    FirewallError  — base exception
    FirewallConnectionError — raised when the sidecar is unreachable
    FirewallBlocked — raised by adapters on BLOCK decisions

Schema contracts:
    ValidateRequest  — typed request envelope (SDK → sidecar)
    ValidateResponse — typed response envelope (sidecar → SDK)
    Signal           — named risk signal with score
    HookType         — on_prompt | on_context | on_tool_call | on_memory
    ProvenanceType   — user | rag | agent | sdk | system
"""
from .contracts import (
    HookType,
    ProvenanceType,
    Signal,
    ValidateRequest,
    ValidateResponse,
)
from .firewall import Firewall
from .models import (
    ChunkResult,
    Decision,
    FirewallBlocked,
    FirewallConnectionError,
    FirewallError,
    SanitiseResult,
)

__all__ = [
    "Firewall",
    "Decision",
    "SanitiseResult",
    "ChunkResult",
    "FirewallBlocked",
    "FirewallError",
    "FirewallConnectionError",
    "ValidateRequest",
    "ValidateResponse",
    "Signal",
    "HookType",
    "ProvenanceType",
]
