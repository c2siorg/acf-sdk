from acf_sdk.client import ACFProtector

# Initialize the Security Guard
guard = ACFProtector()

# Imagine this is your actual AI Chatbot function
@guard.protect
def ask_llm(prompt):
    return f"LLM Response: Hello! You asked about '{prompt}'"

print("--- ACF SDK LIVE DEMO ---")

# 1. TEST A CLEAN PROMPT
print("\n[SCENARIO 1] Sending a safe question...")
response_1 = ask_llm("What is the capital of France?")
print(f"RESULT: {response_1}")

# 2. TEST AN ATTACK (Base64 SQL Injection)
print("\n[SCENARIO 2] Sending a malicious attack...")
# This is "KEEP DOING SELECT * FROM USERS" encoded in Base64
attack_payload = "S0VFRVAgRE9JTkcgU0VMRUNUICogRlJPTSBVU0VSUw=="
response_2 = ask_llm(attack_payload)
print(f"RESULT: {response_2}")