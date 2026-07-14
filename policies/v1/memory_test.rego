# ACF-SDK — Memory Hook Policy Tests
# Validates: hmac_verify, hmac_stamp, provenance_tag, trust_weight,
#            content_scan, entry_size_limit

package acf.policy.memory_test

import future.keywords.in
import data.acf.policy.memory

# =====================================================================
# Integrity — read-time HMAC verify
# =====================================================================

test_read_valid_hmac_allow if {
    result := memory.decision with input as {
        "memory_op": "read",
        "score": 0.0,
        "signals": [],
        "provenance": "internal", "session_id": "s1", "hook_type": "on_memory",
        "integrity": {"hmac_valid": true},
        "payload_size_bytes": 100,
    }
    result == "ALLOW"
}

test_read_invalid_hmac_block if {
    result := memory.decision with input as {
        "memory_op": "read",
        "score": 0.0,
        "signals": [],
        "provenance": "internal", "session_id": "s1", "hook_type": "on_memory",
        "integrity": {"hmac_valid": false},
        "payload_size_bytes": 100,
    }
    result == "BLOCK"
}

test_read_missing_hmac_block if {
    result := memory.decision with input as {
        "memory_op": "read",
        "score": 0.0,
        "signals": [],
        "provenance": "agent", "session_id": "s1", "hook_type": "on_memory",
        "payload_size_bytes": 100,
    }
    result == "BLOCK"
}

test_read_null_hmac_block if {
    result := memory.decision with input as {
        "memory_op": "read",
        "score": 0.0,
        "signals": [],
        "provenance": "agent", "session_id": "s1", "hook_type": "on_memory",
        "integrity": {"hmac_valid": null},
        "payload_size_bytes": 100,
    }
    result == "BLOCK"
}

# =====================================================================
# Integrity — write-time HMAC stamp
# =====================================================================

# When provenance is present, tag_provenance subsumes stamp_hmac.
# The pipeline stamps HMAC whenever it processes a tag_provenance action.
# stamp_hmac only fires as a fallback when provenance is absent.
test_write_clean_tags_provenance if {
    m := memory.metadata with input as {
        "memory_op": "write",
        "score": 0.1,
        "signals": [],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_memory",
        "payload_size_bytes": 100,
    }
    m.action == "tag_provenance"
    m.trust_level == "unverified"
}

# =====================================================================
# Trust — write provenance tag (internal = verified)
# =====================================================================

test_write_internal_provenance_verified if {
    m := memory.metadata with input as {
        "memory_op": "write",
        "score": 0.1,
        "signals": [],
        "provenance": "internal", "session_id": "s1", "hook_type": "on_memory",
        "payload_size_bytes": 100,
    }
    m.action == "tag_provenance"
    m.trust_level == "verified"
}

test_write_external_provenance_unverified if {
    m := memory.metadata with input as {
        "memory_op": "write",
        "score": 0.1,
        "signals": [],
        "provenance": "external", "session_id": "s1", "hook_type": "on_memory",
        "payload_size_bytes": 100,
    }
    m.action == "tag_provenance"
    m.trust_level == "unverified"
}

# =====================================================================
# Trust — read-time low trust marker
# =====================================================================

test_read_low_trust_marker if {
    m := memory.metadata with input as {
        "memory_op": "read",
        "score": 0.2,
        "signals": [{"category": "low_trust_source", "score": 0.7}],
        "provenance": "external", "session_id": "s1", "hook_type": "on_memory",
        "integrity": {"hmac_valid": true},
        "payload_size_bytes": 100,
    }
    m.action == "low_trust_marker"
}

# =====================================================================
# Detection — write-time content scan → SANITISE
# =====================================================================

test_write_content_scan_sanitise if {
    result := memory.decision with input as {
        "memory_op": "write",
        "score": 0.3,
        "signals": [{"category": "content_scan", "score": 0.6}],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_memory",
        "payload_size_bytes": 100,
    }
    result == "SANITISE"
}

test_write_content_scan_targets if {
    targets := memory.sanitise_targets with input as {
        "memory_op": "write",
        "score": 0.3,
        "signals": [{"category": "content_scan", "score": 0.6}],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_memory",
        "payload_size_bytes": 100,
    }
    "memory_value" in targets
}

test_write_content_scan_below_threshold_allow if {
    result := memory.decision with input as {
        "memory_op": "write",
        "score": 0.1,
        "signals": [{"category": "content_scan", "score": 0.3}],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_memory",
        "payload_size_bytes": 100,
    }
    result == "ALLOW"
}

# =====================================================================
# Containment — memory entry size limit → BLOCK
# =====================================================================

test_oversized_entry_block if {
    result := memory.decision with input as {
        "memory_op": "write",
        "score": 0.1,
        "signals": [],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_memory",
        "payload_size_bytes": 20000,
    }
    result == "BLOCK"
}

test_normal_size_entry_allow if {
    result := memory.decision with input as {
        "memory_op": "write",
        "score": 0.1,
        "signals": [],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_memory",
        "payload_size_bytes": 8000,
    }
    result == "ALLOW"
}

test_custom_size_limit if {
    result := memory.decision with input as {
        "memory_op": "write",
        "score": 0.1,
        "signals": [],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_memory",
        "payload_size_bytes": 5000,
    }
        with data.config.max_memory_entry_bytes as 4096
    result == "BLOCK"
}

# =====================================================================
# Size limit overrides content scan — block before sanitise
# =====================================================================

test_oversized_with_content_scan_blocks if {
    result := memory.decision with input as {
        "memory_op": "write",
        "score": 0.3,
        "signals": [{"category": "content_scan", "score": 0.7}],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_memory",
        "payload_size_bytes": 20000,
    }
    result == "BLOCK"
}

# =====================================================================
# Clean write — no signals, small payload → ALLOW
# =====================================================================

test_clean_write_allow if {
    result := memory.decision with input as {
        "memory_op": "write",
        "score": 0.0,
        "signals": [],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_memory",
        "payload_size_bytes": 100,
    }
    result == "ALLOW"
}
