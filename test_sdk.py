import struct
import os
import sys

# The address of our Go "Security Guard"
pipe_path = r'\\.\pipe\acf_security_pipe'
# This is a Base64 encoded "SELECT * FROM USERS" attack
prompt = "S0VFRVAgRE9JTkcgU0VMRUNUICogRlJPTSBVU0VSUw==" 

print(f"[*] Starting ACF SDK Test Client...")

if not os.path.exists(pipe_path):
    print(f"[!] ERROR: Go Sidecar is NOT running. Run 'build.bat run' in another terminal first.")
    sys.exit(1)

try:
    print(f"[*] Connecting to Go Sidecar at {pipe_path}...")
    # Open the pipe for reading and writing in binary mode
    with open(pipe_path, 'r+b', buffering=0) as f:
        print(f"[*] Sending Attack Payload: {prompt}")
        f.write(prompt.encode('utf-8'))
        
        print("[*] Waiting for Security Bitmask...")
        res = f.read(2) # We expect exactly 2 bytes (uint16)
        
        if len(res) < 2:
            print("[!] ERROR: Received incomplete data from Go.")
        else:
            # Unpack the 16-bit integer (Little Endian)
            mask = struct.unpack('<H', res)[0]
            print(f"\n[SUCCESS] Response Received!")
            print(f"Binary Mask: {bin(mask).zfill(18)}") # Shows the bits
            
            # Check Bit 2 (SQL Injection) which is 1 << 2 (decimal 4)
            if mask & 4:
                print(">>> DECISION: [!!!] BLOCK - SQL INJECTION DETECTED [!!!]")
            else:
                print(">>> DECISION: PASS - Payload is clean.")

except Exception as e:
    print(f"[!] PIPE ERROR: {e}")