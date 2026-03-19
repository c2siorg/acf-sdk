@dataclass 
class ValidateRequest: 
    input: str 
    agent_id: str 
    trace_id: str 
    policy_version: str 
    timestamp_utc: str 
    memory_snapshot: list[str] 
