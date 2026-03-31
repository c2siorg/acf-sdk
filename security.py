import os, hmac, hashlib, struct

# Official Key and Pipe
import os, hmac, hashlib, struct, secrets

# 🛡️ SECURE KEY LOADING
# 1. Try to pull the official key from the environment.
# 2. If missing, generate a cryptographically secure random 32-byte key.
# This prevents hardcoded credential leakage in GitHub history.
HMAC_KEY_HEX = os.getenv("ACF_HMAC_KEY")
if HMAC_KEY_HEX:
    HMAC_KEY = bytes.fromhex(HMAC_KEY_HEX)
else:
    # Generate a one-time key for this session if none is provided
    HMAC_KEY = secrets.token_bytes(32)
PIPE_NAME = r'\\.\pipe\acf'

def send_to_kernel(text):
    payload = text.encode('utf-8')
    nonce, version, magic = os.urandom(20), 1, 0xAC
    
    # 1. Sign the message (Phase 1 logic: Ver + Nonce + Payload)
    msg_to_sign = struct.pack(">B20s", version, nonce) + payload
    signature = hmac.new(HMAC_KEY, msg_to_sign, hashlib.sha256).digest()
    
    # 2. Build the 54-byte header + payload
    header = struct.pack(">BB20s32s", magic, version, nonce, signature)
    frame = header + payload
    
    try:
        # Use os.open for low-level control over the pipe
        fd = os.open(PIPE_NAME, os.O_RDWR | os.O_BINARY)
        
        # Write the frame
        os.write(fd, frame)
        
        # IMPORTANT: We must signal the end of the write stream 
        # so Go's io.ReadAll(r) can proceed.
        # In a real SDK, we'd use a protocol-level length, but for 
        # a raw io.ReadAll smoke test, closing the write-side is key.
        
        res = os.read(fd, 5) # Read the 5-byte decision
        os.close(fd)

        if res and res[0] == 0:
            return "✅ ALLOW"
        return "🚫 BLOCK"
    except Exception as e:
        return f"❌ ERR: {e}"

print(f"\nTEST RESULT: {send_to_kernel('Phase 1 Smoke Test')}")