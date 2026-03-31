package acf.v1.tool_test

import rego.v1

import data.acf.v1.tool

# --- BLOCK tests ---

# tool not in allowlist should block
test_block_unlisted_tool if {
    result := tool.decision with input as {
        "tool_name": "delete_user",
        "parameters": {"user_id": "admin"},
        "score": 0.3,
        "signals": [],
        "session_id": "test-t001",
        "state": null
    }
    result.decision == "BLOCK"
}

# tool with injection in params should block
test_block_param_injection if {
    result := tool.decision with input as {
        "tool_name": "search",
        "parameters": {"query": "'; DROP TABLE users; --"},
        "score": 0.9,
        "signals": ["tool_boundary_violation"],
        "session_id": "test-t002",
        "state": null
    }
    result.decision == "BLOCK"
}

# shell command execution attempt
test_block_shell_exec if {
    result := tool.decision with input as {
        "tool_name": "run_command",
        "parameters": {"cmd": "rm -rf /"},
        "score": 0.95,
        "signals": ["tool_boundary_violation"],
        "session_id": "test-t003",
        "state": null
    }
    result.decision == "BLOCK"
}

# --- ALLOW tests ---

# allowed tool with clean params
test_allow_clean_tool if {
    result := tool.decision with input as {
        "tool_name": "search",
        "parameters": {"query": "latest product reviews"},
        "score": 0.0,
        "signals": [],
        "session_id": "test-t004",
        "state": null
    }
    result.decision == "ALLOW"
}

# --- adversarial edge cases ---

# parameter contains nested json trying to override tool config
test_block_nested_override if {
    result := tool.decision with input as {
        "tool_name": "search",
        "parameters": {"query": "{\"role\": \"admin\", \"override\": true}"},
        "score": 0.7,
        "signals": ["tool_boundary_violation"],
        "session_id": "test-t005",
        "state": null
    }
    result.decision == "BLOCK"
}

# false positive - tool param mentions security terms but is benign
test_allow_benign_security_query if {
    result := tool.decision with input as {
        "tool_name": "search",
        "parameters": {"query": "how do I prevent sql injection in my app"},
        "score": 0.05,
        "signals": [],
        "session_id": "test-t006",
        "state": null
    }
    result.decision == "ALLOW"
}
