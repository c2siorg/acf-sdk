"""
Data models for the ACF SDK.

Decision       — ALLOW | SANITISE | BLOCK enum returned by all hook calls.
SanitiseResult — returned on SANITISE decisions; contains the scrubbed payload.
ChunkResult    — returned by on_context; per-chunk decision and sanitised text.
FirewallError  — base exception for all ACF SDK errors.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Optional


class Decision(enum.Enum):
    """The three possible enforcement outcomes."""
    ALLOW    = 0x00
    SANITISE = 0x01
    BLOCK    = 0x02

    @classmethod
    def from_byte(cls, b: int) -> "Decision":
        """Return the Decision corresponding to a response byte.

        Raises ValueError for any unrecognised byte.
        """
        for member in cls:
            if member.value == b:
                return member
        raise ValueError(f"Unknown decision byte: {b:#04x}")


@dataclass
class SanitiseResult:
    """Returned when the sidecar decides SANITISE.

    The caller should use ``sanitised_text`` in place of the original input.
    """
    decision: Decision                   # always Decision.SANITISE
    sanitised_payload: bytes             # raw bytes from the response frame
    sanitised_text: Optional[str] = None # UTF-8 decoded, or None if decoding fails


@dataclass
class ChunkResult:
    """Per-chunk result returned by ``Firewall.on_context``."""
    original: str
    decision: Decision
    sanitised_text: Optional[str] = None


class FirewallError(Exception):
    """Base exception for ACF SDK errors."""


class FirewallConnectionError(FirewallError):
    """Raised when the transport cannot connect to the sidecar after all retries."""
