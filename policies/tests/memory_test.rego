# ACF-SDK adversarial fixtures for the on_memory hook
# Drives data.acf.policy.memory: read-time HMAC verification, write-time content
# scan (SANITISE), and the entry-size limit. Cross-session reads and stateless
# trust escalation are tracked gaps, listed in the PR description.

package acf.adversarial.memory_test

import future.keywords.in
import data.acf.policy.memory

# --- Integrity: read-time HMAC ---

# A tampered stored entry (HMAC mismatch) is blocked on read.
test_read_hmac_invalid_block if {
	result := memory.decision with input as {
		"memory_op": "read",
		"integrity": {"hmac_valid": false},
		"score": 0.0,
		"signals": [],
		"provenance": "memory", "session_id": "m-001", "hook_type": "on_memory",
		"payload_size_bytes": 100,
	}
	result == "BLOCK"
}

test_read_hmac_valid_allow if {
	result := memory.decision with input as {
		"memory_op": "read",
		"integrity": {"hmac_valid": true},
		"score": 0.0,
		"signals": [],
		"provenance": "memory", "session_id": "m-002", "hook_type": "on_memory",
		"payload_size_bytes": 100,
	}
	result == "ALLOW"
}

# --- Detection: write-time content scan ---

# A poisoned write flagged by the content scanner is stripped (SANITISE).
test_write_content_scan_sanitise if {
	result := memory.decision with input as {
		"memory_op": "write",
		"integrity": {"hmac_valid": true},
		"score": 0.6,
		"signals": [{"category": "content_scan", "score": 0.7}],
		"provenance": "tool_output", "session_id": "m-003", "hook_type": "on_memory",
		"payload_size_bytes": 100,
	}
	result == "SANITISE"
}

test_write_content_scan_target if {
	targets := memory.sanitise_targets with input as {
		"memory_op": "write",
		"integrity": {"hmac_valid": true},
		"score": 0.6,
		"signals": [{"category": "content_scan", "score": 0.7}],
		"provenance": "tool_output", "session_id": "m-004", "hook_type": "on_memory",
		"payload_size_bytes": 100,
	}
	"memory_value" in targets
}

# A jailbreak pattern smuggled into a write is also stripped.
test_write_jailbreak_pattern_sanitise if {
	result := memory.decision with input as {
		"memory_op": "write",
		"integrity": {"hmac_valid": true},
		"score": 0.3,
		"signals": [{"category": "jailbreak_pattern", "score": 0.3}],
		"provenance": "tool_output", "session_id": "m-005", "hook_type": "on_memory",
		"payload_size_bytes": 100,
	}
	result == "SANITISE"
}

# --- Containment: entry-size limit ---

# Oversized writes (exfiltration / DoS shape) are blocked.
test_write_oversize_block if {
	result := memory.decision with input as {
		"memory_op": "write",
		"integrity": {"hmac_valid": true},
		"score": 0.1,
		"signals": [],
		"provenance": "user", "session_id": "m-006", "hook_type": "on_memory",
		"payload_size_bytes": 20000,
	}
	result == "BLOCK"
}

# --- Clean traffic ---

test_clean_write_allow if {
	result := memory.decision with input as {
		"memory_op": "write",
		"integrity": {"hmac_valid": true},
		"score": 0.0,
		"signals": [],
		"provenance": "user", "session_id": "m-007", "hook_type": "on_memory",
		"payload_size_bytes": 100,
	}
	result == "ALLOW"
}

test_clean_read_allow if {
	result := memory.decision with input as {
		"memory_op": "read",
		"integrity": {"hmac_valid": true},
		"score": 0.0,
		"signals": [],
		"provenance": "memory", "session_id": "m-008", "hook_type": "on_memory",
		"payload_size_bytes": 100,
	}
	result == "ALLOW"
}
