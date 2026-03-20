"""
Firewall — the main developer-facing class.

Provides the four v1 hook call sites:
  on_prompt(text)             -> Decision
  on_context(chunks)          -> list[ChunkResult]
  on_tool_call(name, params)  -> Decision
  on_memory(key, value, op)   -> Decision

Each method builds a RiskContext JSON payload, delegates to Transport,
and returns the decoded Decision (or raises FirewallError on failure).
"""
from __future__ import annotations

import binascii
import json
import os
from typing import Any

from .models import (
    ChunkResult,
    Decision,
    FirewallError,
    SanitiseResult,
)
from .transport import Transport, DEFAULT_SOCKET_PATH


class Firewall:
    """Entry point for the ACF SDK.

    Args:
        socket_path: Path to the sidecar IPC address. Defaults to
                     ``/tmp/acf.sock`` on Linux/macOS or ``\\\\.\\pipe\\acf``
                     on Windows, or the ACF_SOCKET_PATH environment variable.
        hmac_key:    Raw bytes of the HMAC key. If None, read ACF_HMAC_KEY
                     from the environment (hex-encoded) and decode it.

    Raises:
        FirewallError: If no HMAC key can be resolved.
    """

    def __init__(
        self,
        socket_path: str | None = None,
        hmac_key: bytes | None = None,
    ) -> None:
        resolved_path = (
            socket_path
            or os.environ.get("ACF_SOCKET_PATH")
            or DEFAULT_SOCKET_PATH
        )

        if hmac_key is None:
            raw = os.environ.get("ACF_HMAC_KEY", "")
            if not raw:
                raise FirewallError(
                    "No HMAC key provided. Pass hmac_key= or set ACF_HMAC_KEY "
                    "(hex-encoded, min 32 bytes)."
                )
            try:
                hmac_key = binascii.unhexlify(raw)
            except (ValueError, binascii.Error) as exc:
                raise FirewallError(f"ACF_HMAC_KEY is not valid hex: {exc}") from exc

        self._transport = Transport(socket_path=resolved_path, key=hmac_key)

    # ── v1 hook call sites ────────────────────────────────────────────────────

    def on_prompt(self, text: str) -> Decision | SanitiseResult:
        """Evaluate a user prompt before it enters the model context.

        Returns Decision.ALLOW, Decision.BLOCK, or a SanitiseResult.
        """
        payload = self._build_payload("on_prompt", text, provenance="user")
        return self._send(payload)

    def on_context(self, chunks: list[str]) -> list[ChunkResult]:
        """Evaluate RAG chunks before injection into the model context.

        Each chunk is evaluated independently. Returns one ChunkResult per chunk.
        Chunks with a BLOCK decision have sanitised_text=None.
        """
        results = []
        for chunk in chunks:
            payload  = self._build_payload("on_context", chunk, provenance="rag")
            decision = self._send(payload)
            if isinstance(decision, SanitiseResult):
                results.append(ChunkResult(
                    original=chunk,
                    decision=Decision.SANITISE,
                    sanitised_text=decision.sanitised_text,
                ))
            else:
                results.append(ChunkResult(
                    original=chunk,
                    decision=decision,
                    sanitised_text=None,
                ))
        return results

    def on_tool_call(self, name: str, params: dict[str, Any]) -> Decision | SanitiseResult:
        """Evaluate a tool call before the tool executes.

        Returns Decision.ALLOW, Decision.BLOCK, or a SanitiseResult.
        """
        payload = self._build_payload(
            "on_tool_call",
            {"name": name, "params": params},
            provenance="agent",
        )
        return self._send(payload)

    def on_memory(self, key: str, value: str, op: str = "write") -> Decision | SanitiseResult:
        """Evaluate a memory read or write before it is committed.

        op: "write" (default) or "read".
        Returns Decision.ALLOW, Decision.BLOCK, or a SanitiseResult.
        """
        payload = self._build_payload(
            "on_memory",
            {"key": key, "value": value, "op": op},
            provenance="agent",
        )
        return self._send(payload)

    # ── internals ────────────────────────────────────────────────────────────

    def _build_payload(
        self,
        hook_type: str,
        content: Any,
        *,
        provenance: str = "sdk",
        session_id: str = "",
    ) -> bytes:
        ctx = {
            "score":       0.0,
            "signals":     [],
            "provenance":  provenance,
            "session_id":  session_id,
            "hook_type":   hook_type,
            "payload":     content,
            "state":       None,
        }
        return json.dumps(ctx, separators=(",", ":")).encode("utf-8")

    def _send(self, payload: bytes) -> Decision | SanitiseResult:
        resp     = self._transport.send(payload)
        decision = Decision.from_byte(resp["decision"])

        if decision == Decision.SANITISE:
            raw  = resp["sanitised_payload"]
            text = raw.decode("utf-8", errors="replace") if raw else None
            return SanitiseResult(
                decision=decision,
                sanitised_payload=raw,
                sanitised_text=text,
            )
        return decision
