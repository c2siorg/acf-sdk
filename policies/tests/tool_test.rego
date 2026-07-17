# ACF-SDK adversarial fixtures for the on_tool_call hook
# Drives data.acf.policy.tool, which is fail-closed (default BLOCK). Covers the
# allowlist gate, the network-destination gate, the injection detection signals
# (parameter_injection, shell_metacharacter, path_traversal), and the graduated
# threshold. Tool-parameter structural overrides that carry no detection signal are
# a tracked gap, listed in the PR description.

package acf.adversarial.tool_test

import future.keywords.in
import data.acf.policy.tool

# --- Permission: allowlist (fail-closed) ---

test_unlisted_tool_block if {
	result := tool.decision with input as {
		"tool_name": "delete_user",
		"score": 0.3,
		"signals": [],
		"provenance": "sdk", "session_id": "t-001", "hook_type": "on_tool_call",
		"tool_metadata": {},
	}
		with data.config.tool_allowlist as ["web_search", "calculator"]
	result == "BLOCK"
}

test_allowed_tool_allow if {
	result := tool.decision with input as {
		"tool_name": "web_search",
		"score": 0.1,
		"signals": [],
		"provenance": "sdk", "session_id": "t-002", "hook_type": "on_tool_call",
		"tool_metadata": {},
	}
		with data.config.tool_allowlist as ["web_search", "calculator"]
	result == "ALLOW"
}

test_no_allowlist_allows_all if {
	result := tool.decision with input as {
		"tool_name": "any_tool",
		"score": 0.1,
		"signals": [],
		"provenance": "sdk", "session_id": "t-003", "hook_type": "on_tool_call",
		"tool_metadata": {},
	}
	result == "ALLOW"
}

# --- Permission: network destination ---

test_allowed_destination_allow if {
	result := tool.decision with input as {
		"tool_name": "http_request",
		"score": 0.1,
		"signals": [],
		"provenance": "sdk", "session_id": "t-004", "hook_type": "on_tool_call",
		"tool_metadata": {"destination": "api.example.com"},
	}
		with data.config.tool_allowlist as ["http_request"]
		with data.config.destination_allowlist as ["api.example.com"]
	result == "ALLOW"
}

# Exfiltration to an unlisted host is blocked.
test_blocked_destination_block if {
	result := tool.decision with input as {
		"tool_name": "http_request",
		"score": 0.1,
		"signals": [],
		"provenance": "sdk", "session_id": "t-005", "hook_type": "on_tool_call",
		"tool_metadata": {"destination": "evil.attacker.com"},
	}
		with data.config.tool_allowlist as ["http_request"]
		with data.config.destination_allowlist as ["api.example.com"]
	result == "BLOCK"
}

# --- Detection signals → BLOCK ---

test_parameter_injection_block if {
	result := tool.decision with input as {
		"tool_name": "sql_query",
		"score": 0.3,
		"signals": [{"category": "parameter_injection", "score": 0.8}],
		"provenance": "sdk", "session_id": "t-006", "hook_type": "on_tool_call",
		"tool_metadata": {},
	}
		with data.config.tool_allowlist as ["sql_query"]
	result == "BLOCK"
}

test_shell_metacharacter_block if {
	result := tool.decision with input as {
		"tool_name": "run_command",
		"score": 0.2,
		"signals": [{"category": "shell_metacharacter", "score": 0.6}],
		"provenance": "sdk", "session_id": "t-007", "hook_type": "on_tool_call",
		"tool_metadata": {},
	}
		with data.config.tool_allowlist as ["run_command"]
	result == "BLOCK"
}

test_path_traversal_block if {
	result := tool.decision with input as {
		"tool_name": "read_file",
		"score": 0.2,
		"signals": [{"category": "path_traversal", "score": 0.7}],
		"provenance": "sdk", "session_id": "t-008", "hook_type": "on_tool_call",
		"tool_metadata": {},
	}
		with data.config.tool_allowlist as ["read_file"]
	result == "BLOCK"
}

# --- Containment threshold ---

test_threshold_high_block if {
	result := tool.decision with input as {
		"tool_name": "web_search",
		"score": 0.85,
		"signals": [],
		"provenance": "sdk", "session_id": "t-009", "hook_type": "on_tool_call",
		"tool_metadata": {},
	}
		with data.config.tool_allowlist as ["web_search"]
	result == "BLOCK"
}

test_threshold_medium_sanitise if {
	result := tool.decision with input as {
		"tool_name": "web_search",
		"score": 0.55,
		"signals": [],
		"provenance": "sdk", "session_id": "t-010", "hook_type": "on_tool_call",
		"tool_metadata": {},
	}
		with data.config.tool_allowlist as ["web_search"]
	result == "SANITISE"
}

# --- Permission: destination gate with configured allowlist ---

# An allowed tool calling an unlisted destination is blocked when the
# allowlist is present. This is the production-config scenario: the sidecar
# loads policy_config.yaml as data.config (engine.go:229). Before this fix,
# the key was absent from policy_config.yaml so the gate was permanently open.
test_destination_gate_blocks_unlisted if {
	result := tool.decision with input as {
		"tool_name": "http_request",
		"score": 0.1,
		"signals": [],
		"provenance": "agent", "session_id": "t-013", "hook_type": "on_tool_call",
		"tool_metadata": {"destination": "evil.exfil.example"},
	}
		with data.config.tool_allowlist as ["http_request"]
		with data.config.destination_allowlist as ["api.example.com", "cdn.example.com"]
	result == "BLOCK"
}

# A tool call with no destination field passes regardless of allowlist config.
test_no_destination_field_passes if {
	result := tool.decision with input as {
		"tool_name": "calculator",
		"score": 0.1,
		"signals": [],
		"provenance": "agent", "session_id": "t-014", "hook_type": "on_tool_call",
		"tool_metadata": {},
	}
		with data.config.tool_allowlist as ["calculator"]
		with data.config.destination_allowlist as ["api.example.com"]
	result == "ALLOW"
}

# --- False-positive / boundary guards ---

# A detection signal below the 0.5 confidence cut is not treated as a hit.
test_subthreshold_detection_allow if {
	result := tool.decision with input as {
		"tool_name": "calculator",
		"score": 0.1,
		"signals": [{"category": "parameter_injection", "score": 0.4}],
		"provenance": "sdk", "session_id": "t-012", "hook_type": "on_tool_call",
		"tool_metadata": {},
	}
		with data.config.tool_allowlist as ["calculator"]
	result == "ALLOW"
}
