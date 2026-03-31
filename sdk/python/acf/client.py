import os
import socket
import hmac
import hashlib
import struct
import json
from enum import Enum
from typing import Optional, Dict, Any

class Decision(Enum):
    ALLOW = "ALLOW"
    SANITISE = "SANITISE"
    BLOCK = "BLOCK"
    ERROR = "ERROR"

class Firewall:
    def __init__(self, socket_path: str = "/tmp/acf.sock"):
        # 1. Load HMAC Key (Tharindu's requirement)
        self.key = os.getenv("ACF_HMAC_KEY")
        if not self.key:
            raise ValueError("ACF_HMAC_KEY environment variable not set.")
        self.secret = bytes.fromhex(self.key)
        
        # 2. Setup IPC (Named Pipe for Windows, UDS for Unix)
        self.socket_path = os.getenv("ACF_SOCKET_PATH", socket_path)
        self.is_windows = os.name == 'nt'
        if self.is_windows and not self.socket_path.startswith("\\\\.\\pipe\\"):
            self.socket_path = r"\\.\pipe\acf_security_pipe"

    def _send_frame(self, payload: str, hook_type: str) -> Dict[str, Any]:
        """Wraps payload in a Secure Binary Frame (Magic 0xAC) and dispatches."""
        try:
            # Prepare data
            data = json.dumps({"payload": payload, "hook": hook_type}).encode('utf-8')
            nonce = os.urandom(16)
            version = 1
            
            # Create HMAC (Defence-in-Depth)
            # Layout: Version(1) + Length(4) + Nonce(16) + Payload
            header = struct.pack(">B I 16s", version, len(data), nonce)
            signature = hmac.new(self.secret, header + data, hashlib.sha256).digest()
            
            # Full Frame: Magic(1) + Header(21) + HMAC(32) + Payload
            magic_byte = b'\xAC'
            full_frame = magic_byte + header + signature + data

            # IPC Dispatch
            if self.is_windows:
                with open(self.socket_path, 'rb+', buffering=0) as pipe:
                    pipe.write(full_frame)
                    response = pipe.read(1024)
            else:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                    client.connect(self.socket_path)
                    client.sendall(full_frame)
                    response = client.recv(1024)

            return json.loads(response.decode('utf-8'))
        except Exception as e:
            return {"decision": "ERROR", "reason": str(e)}

    def on_prompt(self, text: str) -> Decision:
        """Stage 1: Validates user input before it hits the LLM."""
        res = self._send_frame(text, "on_prompt")
        return Decision(res.get("decision", "ERROR"))

    def on_tool_call(self, tool_name: str, args: Dict) -> Decision:
        """Stage 2: Validates tool execution (Phase 2.5)."""
        payload = json.dumps({"tool": tool_name, "args": args})
        res = self._send_frame(payload, "on_tool_call")
        return Decision(res.get("decision", "ERROR"))