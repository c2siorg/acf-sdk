"""
Firewall — the main developer-facing class.

Provides the four v1 hook call sites:
  on_prompt(text)             -> Decision
  on_context(chunks)          -> list[ChunkResult]
  on_tool_call(name, params)  -> Decision
  on_memory(key, value, op)   -> Decision

Each method builds a RiskContext JSON payload, delegates to Transport,
and returns the decoded Decision (or raises FirewallError on failure).

Optional: the semantic scanner can be enabled to pre-populate signals in
the RiskContext before sending. When enabled, the scanner runs in the SDK
and emits SemanticHit results that map to Signal objects the sidecar
already understands. The sidecar's scan stage appends its lexical signals
on top — both flow into OPA together.
"""
from __future__ import annotations

import binascii
import json
import logging
import os
from typing import Any

from .models import (
    ChunkResult,
    Decision,
    FirewallError,
    SanitiseResult,
)
from .transport import Transport, DEFAULT_SOCKET_PATH

logger = logging.getLogger(__name__)


class Firewall:
    """Entry point for the ACF SDK.

    Args:
        socket_path: Path to the sidecar IPC address. Defaults to
                     ``/tmp/acf.sock`` on Linux/macOS or ``\\\\.\\pipe\\acf``
                     on Windows, or the ACF_SOCKET_PATH environment variable.
        hmac_key:    Raw bytes of the HMAC key. If None, read ACF_HMAC_KEY
                     from the environment (hex-encoded) and decode it.
        enable_semantic_scan:
                     If True, runs the semantic scanner on string payloads
                     before sending, pre-populating signals in the
                     RiskContext. Default False — base SDK stays zero-deps.
                     Can also be set via ACF_SEMANTIC_SCAN env var
                     (true/1/yes or false/0/no). The env var takes
                     precedence over the constructor argument.
                     Requires: pip install acf-sdk[scanners]
        semantic_signal_threshold:
                     Only semantic hits at or above this similarity (0.0-1.0)
                     are forwarded as signals to the sidecar. Defaults to
                     0.85 — high enough to keep TF-IDF surface-overlap noise
                     out of OPA's view. Lower this when using the
                     sentence-transformer backend (which has cleaner
                     separation between attacks and benign text).
        semantic_backend:
                     Embedding backend for the semantic scanner. Use "tfidf"
                     for lightweight/CI environments (no PyTorch needed) or
                     "sentence-transformer" for production accuracy. Can also
                     be set via ACF_SEMANTIC_SCAN_BACKEND env var (env wins).
                     Default: "tfidf".

    Raises:
        FirewallError: If no HMAC key can be resolved, or if semantic
                       scanning is requested but the [scanners] extra is
                       not installed.
    """

    def __init__(
        self,
        socket_path: str | None = None,
        hmac_key: bytes | None = None,
        enable_semantic_scan: bool | None = None,
        semantic_signal_threshold: float = 0.85,
        semantic_backend: str = "tfidf",
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

        # Resolve the semantic-scan flag. Env var wins, then constructor
        # arg, then default off. Keeps base SDK zero-deps for users who
        # don't opt in.
        env_flag = os.environ.get("ACF_SEMANTIC_SCAN", "").strip().lower()
        if env_flag in ("true", "1", "yes"):
            enable_semantic_scan = True
        elif env_flag in ("false", "0", "no"):
            enable_semantic_scan = False
        elif enable_semantic_scan is None:
            enable_semantic_scan = False

        self._semantic_scanner = None
        self._semantic_signal_threshold = semantic_signal_threshold
        if enable_semantic_scan:
            try:
                from .scanners import SemanticScanner
            except ImportError as exc:
                raise FirewallError(
                    "Semantic scanning was enabled but the [scanners] extra "
                    "is not installed. Install with: pip install acf-sdk[scanners]"
                ) from exc
            env_backend = os.environ.get("ACF_SEMANTIC_SCAN_BACKEND", "").strip().lower()
            resolved_backend = env_backend if env_backend in ("tfidf", "sentence-transformer") else semantic_backend
            self._semantic_scanner = SemanticScanner(backend=resolved_backend)
            logger.info("acf-sdk: semantic scanner enabled (%s backend)", resolved_backend)

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
        signals = self._run_semantic_scanner(hook_type, content)
        ctx = {
            "score":       0.0,
            "signals":     signals,
            "provenance":  provenance,
            "session_id":  session_id,
            "hook_type":   hook_type,
            "payload":     content,
            "state":       None,
        }
        return json.dumps(ctx, separators=(",", ":"), sort_keys=True).encode("utf-8")

    def _run_semantic_scanner(self, hook_type: str, content: Any) -> list[dict]:
        """Run the semantic scanner on string content and return wire-format signals.

        Returns an empty list if the scanner is disabled, the content isn't
        a usable string, or the scanner produces no hits. Scanner errors are
        logged and swallowed — the sidecar's lexical scan still runs, so a
        scanner failure must not break the request.
        """
        if self._semantic_scanner is None:
            return []

        # The scanner only operates on text. Extract a string from the
        # content if possible; otherwise skip.
        text = self._extract_text(hook_type, content)
        if not text:
            return []

        # Import the scanner types lazily — only needed when enabled.
        from .scanners import InputType, ScanInput, TrustLevel

        hook_to_input_type = {
            "on_prompt":    InputType.PROMPT,
            "on_context":   InputType.RAG_DOCUMENT,
            "on_tool_call": InputType.TOOL_CALL,
            "on_memory":    InputType.MEMORY_WRITE,
        }
        input_type = hook_to_input_type.get(hook_type, InputType.PROMPT)

        scan_input = ScanInput(
            agent_id="sdk",
            execution_id="sdk",
            session_id="sdk",
            input_type=input_type,
            normalized_content=text,
            trust_level=TrustLevel.LOW,
        )

        try:
            result = self._semantic_scanner.scan(scan_input)
        except Exception as exc:  # pragma: no cover — defensive
            logger.warning("acf-sdk: semantic scanner error: %s", exc)
            return []

        # Map SemanticHit → wire-format Signal dict the sidecar already accepts.
        # Filter by signal_threshold first — the scanner's own default_threshold
        # is set lower for in-process reporting; we use a stricter bar before
        # forwarding to the sidecar so weak TF-IDF surface-overlap doesn't
        # become evidence in OPA's view. When users upgrade to the
        # sentence-transformer backend they can drop this threshold.
        return [
            {"category": hit.matched_category, "score": hit.similarity_score}
            for hit in result.semantic_hits
            if hit.similarity_score >= self._semantic_signal_threshold
        ]

    @staticmethod
    def _extract_text(hook_type: str, content: Any) -> str:
        """Pull a string out of the per-hook payload shape.

        on_prompt:    content is already a string
        on_context:   content is a single chunk string
        on_tool_call: content is {"name", "params"} — scan params as JSON
        on_memory:    content is {"key", "value", "op"} — scan the value
        """
        if isinstance(content, str):
            return content
        if isinstance(content, dict):
            if hook_type == "on_tool_call":
                params = content.get("params")
                if isinstance(params, dict) and params:
                    return json.dumps(params, separators=(",", ":"))
                if isinstance(params, str):
                    return params
            if hook_type == "on_memory":
                value = content.get("value")
                if isinstance(value, str) and value:
                    return value
        return ""

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