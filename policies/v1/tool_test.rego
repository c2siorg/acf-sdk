# ACF-SDK — Tool Call Hook Policy Tests
# Validates: tool_allowlist, network_destination, parameter_injection,
#            shell_metacharacter, path_traversal, tool_call_threshold

package acf.policy.tool_test

import future.keywords.in
import data.acf.policy.tool

# =====================================================================
# Permission — tool allowlist
# =====================================================================

test_allowed_tool_passes if {
    result := tool.decision with input as {
        "tool_name": "web_search",
        "score": 0.1,
        "signals": [],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_tool_call",
        "tool_metadata": {},
    }
        with data.config.tool_allowlist as ["web_search", "calculator", "read_file"]
    result == "ALLOW"
}

test_blocked_tool_denied if {
    result := tool.decision with input as {
        "tool_name": "exec_shell",
        "score": 0.1,
        "signals": [],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_tool_call",
        "tool_metadata": {},
    }
        with data.config.tool_allowlist as ["web_search", "calculator"]
    result == "BLOCK"
}

test_no_allowlist_allows_all if {
    result := tool.decision with input as {
        "tool_name": "any_tool",
        "score": 0.1,
        "signals": [],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_tool_call",
        "tool_metadata": {},
    }
    result == "ALLOW"
}

# =====================================================================
# Permission — network destination allowlist
# =====================================================================

test_allowed_destination_passes if {
    result := tool.decision with input as {
        "tool_name": "http_request",
        "score": 0.1,
        "signals": [],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_tool_call",
        "tool_metadata": {"destination": "api.example.com"},
    }
        with data.config.tool_allowlist as ["http_request"]
        with data.config.destination_allowlist as ["api.example.com", "cdn.example.com"]
    result == "ALLOW"
}

test_no_destination_ignores_allowlist if {
    result := tool.decision with input as {
        "tool_name": "calculator",
        "score": 0.1,
        "signals": [],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_tool_call",
        "tool_metadata": {},
    }
        with data.config.tool_allowlist as ["calculator"]
        with data.config.destination_allowlist as ["api.example.com"]
    result == "ALLOW"
}

test_blocked_destination_denied if {
    result := tool.decision with input as {
        "tool_name": "http_request",
        "score": 0.1,
        "signals": [],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_tool_call",
        "tool_metadata": {"destination": "evil.attacker.com"},
    }
        with data.config.tool_allowlist as ["http_request"]
        with data.config.destination_allowlist as ["api.example.com"]
    result == "BLOCK"
}

# =====================================================================
# Detection — parameter injection → BLOCK
# =====================================================================

test_parameter_injection_block if {
    result := tool.decision with input as {
        "tool_name": "sql_query",
        "score": 0.3,
        "signals": [{"category": "parameter_injection", "score": 0.8}],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_tool_call",
        "tool_metadata": {},
    }
        with data.config.tool_allowlist as ["sql_query"]
    result == "BLOCK"
}

# =====================================================================
# Detection — shell metacharacter → BLOCK
# =====================================================================

test_shell_metacharacter_block if {
    result := tool.decision with input as {
        "tool_name": "run_command",
        "score": 0.2,
        "signals": [{"category": "shell_metacharacter", "score": 0.6}],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_tool_call",
        "tool_metadata": {},
    }
        with data.config.tool_allowlist as ["run_command"]
    result == "BLOCK"
}

# =====================================================================
# Detection — path traversal → BLOCK
# =====================================================================

test_path_traversal_block if {
    result := tool.decision with input as {
        "tool_name": "read_file",
        "score": 0.2,
        "signals": [{"category": "path_traversal", "score": 0.7}],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_tool_call",
        "tool_metadata": {},
    }
        with data.config.tool_allowlist as ["read_file"]
    result == "BLOCK"
}

# =====================================================================
# Containment — tool call threshold
# =====================================================================

test_high_score_block if {
    result := tool.decision with input as {
        "tool_name": "web_search",
        "score": 0.85,
        "signals": [],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_tool_call",
        "tool_metadata": {},
    }
        with data.config.tool_allowlist as ["web_search"]
    result == "BLOCK"
}

test_medium_score_sanitise if {
    result := tool.decision with input as {
        "tool_name": "web_search",
        "score": 0.55,
        "signals": [],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_tool_call",
        "tool_metadata": {},
    }
        with data.config.tool_allowlist as ["web_search"]
    result == "SANITISE"
}

test_medium_score_sanitise_targets if {
    targets := tool.sanitise_targets with input as {
        "tool_name": "web_search",
        "score": 0.55,
        "signals": [],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_tool_call",
        "tool_metadata": {},
    }
        with data.config.tool_allowlist as ["web_search"]
    "tool_params" in targets
}

test_low_score_allowed_tool_allow if {
    result := tool.decision with input as {
        "tool_name": "calculator",
        "score": 0.1,
        "signals": [],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_tool_call",
        "tool_metadata": {},
    }
        with data.config.tool_allowlist as ["calculator"]
    result == "ALLOW"
}
