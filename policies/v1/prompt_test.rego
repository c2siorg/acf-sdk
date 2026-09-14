# ACF-SDK — Prompt Hook Policy Tests
# Validates: instruction_override, role_escalation, jailbreak_pattern,
#            obfuscation_escalation, policy_integrity, injection_threshold

package acf.policy.prompt_test

import future.keywords.in
import data.acf.policy.prompt

# =====================================================================
# Detection — BLOCK signals
# =====================================================================

test_instruction_override_block if {
    result := prompt.decision with input as {
        "score": 0.3,
        "signals": [{"category": "instruction_override", "score": 0.9}],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_prompt",
    }
    result == "BLOCK"
}

test_instruction_override_below_threshold_allow if {
    result := prompt.decision with input as {
        "score": 0.1,
        "signals": [{"category": "instruction_override", "score": 0.5}],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_prompt",
    }
    result == "ALLOW"
}

test_role_escalation_block if {
    result := prompt.decision with input as {
        "score": 0.2,
        "signals": [{"category": "role_escalation", "score": 0.85}],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_prompt",
    }
    result == "BLOCK"
}

test_jailbreak_pattern_block if {
    result := prompt.decision with input as {
        "score": 0.2,
        "signals": [{"category": "jailbreak_pattern", "score": 0.75}],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_prompt",
    }
    result == "BLOCK"
}

test_obfuscation_escalation_block if {
    result := prompt.decision with input as {
        "score": 0.2,
        "signals": [{"category": "obfuscation_escalation", "score": 0.9}],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_prompt",
    }
    result == "BLOCK"
}

test_policy_integrity_halt if {
    result := prompt.decision with input as {
        "score": 0.0,
        "signals": [{"category": "policy_integrity", "score": 0.1}],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_prompt",
    }
    result == "BLOCK"
}

# =====================================================================
# Containment — injection threshold (graduated)
# =====================================================================

test_high_score_block if {
    result := prompt.decision with input as {
        "score": 0.85,
        "signals": [],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_prompt",
    }
    result == "BLOCK"
}

test_medium_score_sanitise if {
    result := prompt.decision with input as {
        "score": 0.55,
        "signals": [],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_prompt",
    }
    result == "SANITISE"
}

test_score_below_configured_sanitise_threshold_allows if {
    result := prompt.decision with input as {
        "score": 0.45,
        "signals": [],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_prompt",
    }
    result == "ALLOW"
}

test_score_below_configured_block_threshold_sanitises if {
    result := prompt.decision with input as {
        "score": 0.82,
        "signals": [],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_prompt",
    }
    result == "SANITISE"
}

test_medium_score_sanitise_targets if {
    targets := prompt.sanitise_targets with input as {
        "score": 0.55,
        "signals": [],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_prompt",
    }
    "prompt_text" in targets
}

test_low_score_allow if {
    result := prompt.decision with input as {
        "score": 0.2,
        "signals": [],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_prompt",
    }
    result == "ALLOW"
}

test_zero_signals_zero_score_allow if {
    result := prompt.decision with input as {
        "score": 0.0,
        "signals": [],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_prompt",
    }
    result == "ALLOW"
}

# =====================================================================
# Detection overrides containment — hard block takes priority
# =====================================================================

test_detection_overrides_containment if {
    result := prompt.decision with input as {
        "score": 0.5,
        "signals": [{"category": "instruction_override", "score": 0.9}],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_prompt",
    }
    result == "BLOCK"
}

# =====================================================================
# Multiple signals — worst wins
# =====================================================================

test_multiple_signals_worst_wins if {
    result := prompt.decision with input as {
        "score": 0.3,
        "signals": [
            {"category": "role_escalation", "score": 0.4},
            {"category": "jailbreak_pattern", "score": 0.8},
        ],
        "provenance": "sdk", "session_id": "s1", "hook_type": "on_prompt",
    }
    result == "BLOCK"
}
