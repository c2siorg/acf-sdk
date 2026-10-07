"""
IPC client transport for the ACF SDK.

Responsibilities:
  - Sign each payload with HMAC-SHA256 and a fresh per-request nonce
  - Encode the request frame (via frame.py) and write to the IPC channel
  - Read and decode the response frame
  - Retry on transient connection failures (exponential backoff, max 3 attempts)

Platform support:
  - Linux/macOS: Unix Domain Socket (AF_UNIX)
  - Windows: Named pipe via ctypes (no external dependencies)

Zero external dependencies — stdlib only (socket, ctypes, time).
"""
from __future__ import annotations

import math
import os
import platform
import socket
import struct
import time

from .frame import encode_request, decode_response, FrameError
from .models import FirewallConnectionError, FirewallTimeout

_IS_WINDOWS = platform.system() == "Windows"

DEFAULT_SOCKET_PATH = r"\\.\pipe\acf" if _IS_WINDOWS else "/tmp/acf.sock"
MAX_ATTEMPTS        = 3
BACKOFF_BASE        = 0.1  # seconds — doubles on each retry

# Ceiling for a single blocking IPC operation. Deliberately far above any real
# sidecar latency so it only fires when the sidecar is wedged, but tight enough
# that a stalled enforcement path cannot block the calling thread forever.
# This matches the 30s budget the benchmark harnesses already assume.
DEFAULT_TIMEOUT     = 30.0  # seconds


def _clean_timeout(value: float | None, fallback: float | None) -> float | None:
    """Normalise a timeout to a positive finite float, or None for "no ceiling".

    Rejects zero, negatives, NaN and infinity: ``socket.settimeout(0)`` means
    *non-blocking*, not "unbounded", so passing it through would silently break
    every call. NaN and inf raise inside the socket layer, so they are rejected
    here too.
    """
    if value is None:
        return fallback
    try:
        v = float(value)
    except (TypeError, ValueError):
        return fallback
    if not math.isfinite(v) or v <= 0:
        return None if value is not None else fallback
    return v


def _resolve_timeout() -> float | None:
    """Resolve the default timeout from ACF_TIMEOUT_MS.

    Follows the existing ACF_SOCKET_PATH / ACF_HMAC_KEY convention. A value of
    ``0`` disables the ceiling. An unparseable value falls back to
    ``DEFAULT_TIMEOUT`` rather than raising.
    """
    raw = os.environ.get("ACF_TIMEOUT_MS", "").strip()
    if not raw:
        return DEFAULT_TIMEOUT
    try:
        ms = float(raw)
    except ValueError:
        return DEFAULT_TIMEOUT
    if not math.isfinite(ms) or ms <= 0:
        return None
    return ms / 1000.0


class Transport:
    """Low-level IPC client. One new connection is opened per request."""

    def __init__(self, socket_path: str = DEFAULT_SOCKET_PATH, key: bytes = b"",
                 timeout: float | None = None) -> None:
        """Create a transport.

        Args:
            socket_path: IPC address of the sidecar.
            key: HMAC-SHA256 key shared with the sidecar.
            timeout: Ceiling in seconds for a single blocking IPC operation.
                ``None`` reads ``ACF_TIMEOUT_MS`` (falling back to
                ``DEFAULT_TIMEOUT``); ``0`` disables the ceiling and restores
                the previous unbounded behaviour.
        """
        self.socket_path = socket_path
        self.key         = key
        self.timeout     = _clean_timeout(timeout, _resolve_timeout())

    def send(self, payload: bytes) -> dict:
        """Sign and send *payload*, return the decoded response dict.

        Retries up to MAX_ATTEMPTS on ``ConnectionRefusedError`` or
        ``FileNotFoundError`` (sidecar not yet started) using exponential
        backoff. All other ``OSError`` subclasses are re-raised immediately.

        A timeout is **not** retried: the sidecar accepted the connection and
        then stopped responding, so retrying would multiply the latency budget
        rather than recover. Timeouts surface as ``FirewallTimeout``.

        Returns a dict with keys: decision (int), sanitised_payload (bytes).
        Raises FirewallConnectionError after exhausting retries.
        Raises FirewallTimeout when a single attempt exceeds the timeout.
        """
        frame    = encode_request(payload, self.key)
        delay    = BACKOFF_BASE
        last_err: Exception | None = None

        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                raw = self._connect_and_send(frame)
                return decode_response(raw)
            except (ConnectionRefusedError, FileNotFoundError) as exc:
                last_err = exc
                if attempt < MAX_ATTEMPTS:
                    time.sleep(delay)
                    delay *= 2
            except TimeoutError as exc:
                raise FirewallTimeout(
                    f"IPC round trip to {self.socket_path} exceeded "
                    f"{self.timeout}s: {exc}"
                ) from exc

        raise FirewallConnectionError(
            f"Could not connect to sidecar at {self.socket_path} "
            f"after {MAX_ATTEMPTS} attempts: {last_err}"
        )

    def _connect_and_send(self, frame_bytes: bytes) -> bytes:
        """Open a platform connection, write the frame, read the full response."""
        if _IS_WINDOWS:
            return self._connect_and_send_pipe(frame_bytes)
        return self._connect_and_send_uds(frame_bytes)

    def _connect_and_send_uds(self, frame_bytes: bytes) -> bytes:
        """Unix Domain Socket path (Linux/macOS)."""
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            # Bound connect, write and read alike. Without this a sidecar that
            # accepts and then goes quiet blocks the caller indefinitely.
            sock.settimeout(self.timeout)
            sock.connect(self.socket_path)
            sock.sendall(frame_bytes)
            return self._read_response(sock)

    def _connect_and_send_pipe(self, frame_bytes: bytes) -> bytes:
        """Windows named pipe path — stdlib ctypes only."""
        import ctypes
        import ctypes.wintypes as wt

        GENERIC_READ  = 0x80000000
        GENERIC_WRITE = 0x40000000
        OPEN_EXISTING = 3
        FILE_FLAG_OVERLAPPED = 0
        INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

        CreateFile = ctypes.windll.kernel32.CreateFileW
        CreateFile.restype = wt.HANDLE
        CreateFile.argtypes = [
            wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p,
            wt.DWORD, wt.DWORD, wt.HANDLE,
        ]

        handle = CreateFile(
            self.socket_path,
            GENERIC_READ | GENERIC_WRITE,
            0, None, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, None,
        )
        if handle == INVALID_HANDLE_VALUE:
            err = ctypes.windll.kernel32.GetLastError()
            # Error 2 = file not found (pipe not running); map to FileNotFoundError
            # Error 231 = all pipe instances busy; map to ConnectionRefusedError
            if err == 2:
                raise FileNotFoundError(f"Named pipe not found: {self.socket_path}")
            raise ConnectionRefusedError(f"Cannot open named pipe (error {err}): {self.socket_path}")

        try:
            return self._pipe_write_read(handle, frame_bytes)
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)

    @staticmethod
    def _pipe_write_read(handle, frame_bytes: bytes) -> bytes:
        """Write *frame_bytes* to a Win32 HANDLE and read the response."""
        import ctypes
        import ctypes.wintypes as wt

        WriteFile = ctypes.windll.kernel32.WriteFile
        WriteFile.restype = wt.BOOL
        WriteFile.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD), ctypes.c_void_p]

        ReadFile = ctypes.windll.kernel32.ReadFile
        ReadFile.restype = wt.BOOL
        ReadFile.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD), ctypes.c_void_p]

        # Write.
        written = wt.DWORD(0)
        buf = (ctypes.c_char * len(frame_bytes))(*frame_bytes)
        if not WriteFile(handle, buf, len(frame_bytes), ctypes.byref(written), None):
            err = ctypes.windll.kernel32.GetLastError()
            raise OSError(f"WriteFile failed (error {err})")

        # Read the 5-byte response header.
        header_buf = (ctypes.c_char * 5)()
        _read = wt.DWORD(0)
        total = 0
        while total < 5:
            if not ReadFile(handle, ctypes.cast(ctypes.byref(header_buf, total), ctypes.c_void_p), 5 - total, ctypes.byref(_read), None):
                err = ctypes.windll.kernel32.GetLastError()
                raise FrameError(f"ReadFile header failed (error {err})")
            total += _read.value

        header = bytes(header_buf)
        san_len = struct.unpack(">I", header[1:5])[0]

        if san_len == 0:
            return header

        # Read sanitised payload.
        body_buf = (ctypes.c_char * san_len)()
        total = 0
        while total < san_len:
            if not ReadFile(handle, ctypes.cast(ctypes.byref(body_buf, total), ctypes.c_void_p), san_len - total, ctypes.byref(_read), None):
                err = ctypes.windll.kernel32.GetLastError()
                raise FrameError(f"ReadFile body failed (error {err})")
            total += _read.value

        return header + bytes(body_buf)

    @staticmethod
    def _read_response(sock: socket.socket) -> bytes:
        """Read a response frame from a socket."""
        header  = _recv_exact(sock, 5)
        san_len = struct.unpack(">I", header[1:5])[0]
        body    = _recv_exact(sock, san_len) if san_len > 0 else b""
        return header + body


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly *n* bytes from *sock*.

    Depends on the socket timeout set in :meth:`Transport._connect_and_send_uds`;
    a wedged sidecar raises ``TimeoutError`` rather than blocking forever.
    """
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise FrameError(
                f"connection closed after {len(buf)} bytes, expected {n}"
            )
        buf.extend(chunk)
    return bytes(buf)
