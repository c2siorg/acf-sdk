# ACF-SDK adversarial fixtures for the on_context hook
# Drives data.acf.policy.context with retrieved-content attack shapes: structural
# anomalies, embedded (indirect) instructions, source-trust weighting, oversized
# RAG chunks, and the graduated risk threshold on the effective score. Coverage
# gaps (cross-chunk splitting, untyped exfiltration) are listed in the PR description.

package acf.adversarial.context_test

import future.keywords.in
import data.acf.policy.context

# --- Detection ---

# Structural anomaly (smuggled role markers, control bytes) → hard BLOCK.
test_structural_anomaly_block if {
	result := context.decision with input as {
		"score": 0.3,
		"signals": [{"category": "structural_anomaly", "score": 0.9}],
		"provenance": "rag", "session_id": "c-001", "hook_type": "on_context",
		"payload_size_bytes": 200,
	}
	result == "BLOCK"
}

# Indirect injection: a hidden instruction inside retrieved text. The scan stage
# tags it embedded_instruction; the policy strips the chunk via SANITISE.
test_indirect_injection_sanitise if {
	result := context.decision with input as {
		"score": 0.2,
		"signals": [{"category": "embedded_instruction", "score": 0.7}],
		"provenance": "rag", "session_id": "c-002", "hook_type": "on_context",
		"payload_size_bytes": 200,
	}
	result == "SANITISE"
}

test_indirect_injection_strips_chunk if {
	targets := context.sanitise_targets with input as {
		"score": 0.2,
		"signals": [{"category": "embedded_instruction", "score": 0.7}],
		"provenance": "rag", "session_id": "c-003", "hook_type": "on_context",
		"payload_size_bytes": 200,
	}
	"context_chunk" in targets
}

# --- Trust weighting ---

# Low-trust source doubles the effective risk and tips a medium score to BLOCK.
test_low_trust_amplifies_block if {
	result := context.decision with input as {
		"score": 0.5,
		"signals": [{"category": "source_trust", "score": 0.1}],
		"provenance": "external", "session_id": "c-004", "hook_type": "on_context",
		"payload_size_bytes": 200,
	}
	result == "BLOCK"
}

# High-trust source halves the risk and keeps the same score in ALLOW.
test_high_trust_reduces_allow if {
	result := context.decision with input as {
		"score": 0.5,
		"signals": [{"category": "source_trust", "score": 0.8}],
		"provenance": "internal", "session_id": "c-005", "hook_type": "on_context",
		"payload_size_bytes": 200,
	}
	result == "ALLOW"
}

test_default_trust_multiplier if {
	m := context.trust_multiplier with input as {
		"score": 0.3,
		"signals": [],
		"provenance": "sdk", "session_id": "c-006", "hook_type": "on_context",
		"payload_size_bytes": 200,
	}
	m == 1.0
}

# --- Containment ---

# A high generic risk score blocks on its own. An untyped exfiltration request has
# no dedicated rule, so it is caught only when its score lands here (gap notes).
test_high_score_block if {
	result := context.decision with input as {
		"score": 0.9,
		"signals": [],
		"provenance": "rag", "session_id": "c-007", "hook_type": "on_context",
		"payload_size_bytes": 200,
	}
	result == "BLOCK"
}

test_threshold_medium_sanitise if {
	result := context.decision with input as {
		"score": 0.55,
		"signals": [],
		"provenance": "rag", "session_id": "c-008", "hook_type": "on_context",
		"payload_size_bytes": 200,
	}
	result == "SANITISE"
}

# Oversized RAG chunk is split rather than dropped.
test_oversized_chunk_split if {
	result := context.decision with input as {
		"score": 0.1,
		"signals": [],
		"provenance": "rag", "session_id": "c-009", "hook_type": "on_context",
		"payload_size_bytes": 10000,
	}
	result == "SANITISE"
}

test_oversized_chunk_split_target if {
	targets := context.sanitise_targets with input as {
		"score": 0.1,
		"signals": [],
		"provenance": "rag", "session_id": "c-010", "hook_type": "on_context",
		"payload_size_bytes": 10000,
	}
	"split_chunk" in targets
}

# --- Boundary / false-positive guards ---

test_clean_context_allow if {
	result := context.decision with input as {
		"score": 0.1,
		"signals": [],
		"provenance": "rag", "session_id": "c-011", "hook_type": "on_context",
		"payload_size_bytes": 4000,
	}
	result == "ALLOW"
}

# A weak embedded-instruction signal (below the 0.6 cut) is not stripped.
test_subthreshold_embedded_allow if {
	result := context.decision with input as {
		"score": 0.2,
		"signals": [{"category": "embedded_instruction", "score": 0.5}],
		"provenance": "rag", "session_id": "c-012", "hook_type": "on_context",
		"payload_size_bytes": 200,
	}
	result == "ALLOW"
}
