"""
Structured audit logger for the ACF-SDK.

Every ALLOW / SANITISE / BLOCK decision is recorded as a single-line JSON
entry appended to a JSONL file.  Writes use os.O_APPEND for atomicity on
POSIX — a partial write from a crash will never corrupt previous entries.

Sensitive fields (the raw input text) are SHA-256 hashed, not stored in
clear.  The audit log records *what happened*, not *what the user said*.

Usage:
    logger = AuditLogger()                       # default: ./acf_audit.jsonl
    logger = AuditLogger("/var/log/acf.jsonl")   # custom path

    logger.log(
        hook="on_prompt",
        decision="BLOCK",
        score=0.87,
        policy="prompt/instruction_override",
        input_text="ignore previous instructions",
        session_id="abc-123",
        signals=[{"category": "instruction_override", "score": 0.87}],
    )
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class AuditEntry:
    """A single audit log entry."""

    timestamp: str
    hook: str
    decision: str
    score: float
    policy: str
    input_hash: str
    session_id: str
    signals: List[Dict[str, Any]] = field(default_factory=list)
    latency_ms: float = 0.0

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"))


def _hash_input(text: str) -> str:
    """SHA-256 hash of the input text — never store raw content in audit."""
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


class AuditLogger:
    """
    Append-only JSONL audit logger.

    Thread-safety: each write opens the file with O_APPEND, writes one
    line, and closes.  On POSIX, O_APPEND guarantees atomic appends up
    to PIPE_BUF (at least 4096 bytes).  Audit entries are well under
    this limit.
    """

    def __init__(self, path: str = "acf_audit.jsonl") -> None:
        self._path = Path(path)
        # Ensure parent directory exists
        self._path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def path(self) -> Path:
        return self._path

    def log(
        self,
        hook: str,
        decision: str,
        score: float,
        input_text: str,
        session_id: str = "",
        policy: str = "",
        signals: Optional[List[Dict[str, Any]]] = None,
        latency_ms: float = 0.0,
    ) -> AuditEntry:
        """Write an audit entry and return it."""
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            hook=hook,
            decision=decision,
            score=round(score, 4),
            policy=policy,
            input_hash=_hash_input(input_text),
            session_id=session_id,
            signals=signals or [],
            latency_ms=round(latency_ms, 2),
        )
        line = entry.to_json() + "\n"

        # Atomic append — O_APPEND on POSIX
        fd = os.open(str(self._path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        try:
            os.write(fd, line.encode("utf-8"))
        finally:
            os.close(fd)

        return entry

    def read_entries(self) -> List[AuditEntry]:
        """Read all entries from the log (for testing / dashboard)."""
        if not self._path.exists():
            return []
        entries = []
        with open(self._path, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    data = json.loads(line)
                    entries.append(AuditEntry(**data))
        return entries

    def clear(self) -> None:
        """Clear the log file (for testing only)."""
        if self._path.exists():
            self._path.unlink()
