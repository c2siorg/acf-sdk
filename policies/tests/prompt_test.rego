# ACF-SDK adversarial fixtures for the on_prompt hook
# Drives data.acf.policy.prompt with attacker-shaped signal sets and asserts the
# enforced verdict. Signals mirror what the scan stage emits upstream: objects of
# {category, score}, matching the pkg/riskcontext contract. Covers the prompt-facing
# attack classes (instruction override, role escalation, jailbreak library,
# obfuscation, policy tampering), the graduated injection threshold, and the
# false-positive guards. Coverage gaps the current policy cannot block are listed
# in the PR description.

package acf.adversarial.prompt_test

import future.keywords.in
import data.acf.policy.prompt

# --- Detection: hard-block signal classes ---

# DAN-style instruction override: replace the system instruction outright.
test_instruction_override_block if {
	result := prompt.decision with input as {
		"score": 0.3,
		"signals": [{"category": "instruction_override", "score": 0.9}],
		"provenance": "user", "session_id": "p-001", "hook_type": "on_prompt",
	}
	result == "BLOCK"
}

# Role escalation: elevate the model persona ("you are now DAN").
test_role_escalation_block if {
	result := prompt.decision with input as {
		"score": 0.2,
		"signals": [{"category": "role_escalation", "score": 0.85}],
		"provenance": "user", "session_id": "p-002", "hook_type": "on_prompt",
	}
	result == "BLOCK"
}

# Known jailbreak library hit blocks even with a low base score.
test_jailbreak_library_block if {
	result := prompt.decision with input as {
		"score": 0.2,
		"signals": [{"category": "jailbreak_pattern", "score": 0.75}],
		"provenance": "user", "session_id": "p-003", "hook_type": "on_prompt",
	}
	result == "BLOCK"
}

# Heavy obfuscation / encoding escalation.
test_obfuscation_escalation_block if {
	result := prompt.decision with input as {
		"score": 0.2,
		"signals": [{"category": "obfuscation_escalation", "score": 0.9}],
		"provenance": "user", "session_id": "p-004", "hook_type": "on_prompt",
	}
	result == "BLOCK"
}

# Policy tampering halts immediately, regardless of score.
test_policy_integrity_halt if {
	result := prompt.decision with input as {
		"score": 0.0,
		"signals": [{"category": "policy_integrity", "score": 0.1}],
		"provenance": "user", "session_id": "p-005", "hook_type": "on_prompt",
	}
	result == "BLOCK"
}

# --- Containment: graduated injection threshold ---

test_threshold_high_block if {
	result := prompt.decision with input as {
		"score": 0.85,
		"signals": [],
		"provenance": "user", "session_id": "p-006", "hook_type": "on_prompt",
	}
	result == "BLOCK"
}

test_threshold_medium_sanitise if {
	result := prompt.decision with input as {
		"score": 0.55,
		"signals": [],
		"provenance": "user", "session_id": "p-007", "hook_type": "on_prompt",
	}
	result == "SANITISE"
}

test_threshold_low_allow if {
	result := prompt.decision with input as {
		"score": 0.2,
		"signals": [],
		"provenance": "user", "session_id": "p-008", "hook_type": "on_prompt",
	}
	result == "ALLOW"
}

# --- Precedence and multi-signal handling ---

# A hard-block signal wins over a merely medium base score.
test_detection_overrides_score if {
	result := prompt.decision with input as {
		"score": 0.5,
		"signals": [{"category": "instruction_override", "score": 0.9}],
		"provenance": "user", "session_id": "p-009", "hook_type": "on_prompt",
	}
	result == "BLOCK"
}

# Worst signal in the set decides the verdict.
test_multi_signal_worst_wins if {
	result := prompt.decision with input as {
		"score": 0.3,
		"signals": [
			{"category": "role_escalation", "score": 0.4},
			{"category": "jailbreak_pattern", "score": 0.8},
		],
		"provenance": "user", "session_id": "p-010", "hook_type": "on_prompt",
	}
	result == "BLOCK"
}

# --- False-positive guards ---

# A low-confidence detection (below the per-class cut) must not over-block.
test_subthreshold_signal_allow if {
	result := prompt.decision with input as {
		"score": 0.1,
		"signals": [{"category": "instruction_override", "score": 0.5}],
		"provenance": "user", "session_id": "p-012", "hook_type": "on_prompt",
	}
	result == "ALLOW"
}
