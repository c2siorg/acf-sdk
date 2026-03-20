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

import platform
import socket
import struct
import time

from .frame import encode_request, decode_response, FrameError
from .models import FirewallConnectionError

_IS_WINDOWS = platform.system() == "Windows"

DEFAULT_SOCKET_PATH = r"\\.\pipe\acf" if _IS_WINDOWS else "/tmp/acf.sock"
MAX_ATTEMPTS        = 3
BACKOFF_BASE        = 0.1  # seconds — doubles on each retry


class Transport:
    """Low-level IPC client. One new connection is opened per request."""

    def __init__(self, socket_path: str = DEFAULT_SOCKET_PATH, key: bytes = b"") -> None:
        self.socket_path = socket_path
        self.key         = key

    def send(self, payload: bytes) -> dict:
        """Sign and send *payload*, return the decoded response dict.

        Retries up to MAX_ATTEMPTS on ``ConnectionRefusedError`` or
        ``FileNotFoundError`` (sidecar not yet started) using exponential
        backoff. All other ``OSError`` subclasses are re-raised immediately.

        Returns a dict with keys: decision (int), sanitised_payload (bytes).
        Raises FirewallConnectionError after exhausting retries.
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
    """Read exactly *n* bytes from *sock*, blocking until all bytes arrive."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise FrameError(
                f"connection closed after {len(buf)} bytes, expected {n}"
            )
        buf.extend(chunk)
    return bytes(buf)
