package acf.v1.prompt_test

import rego.v1

import data.acf.v1.prompt

# --- BLOCK tests ---

# direct instruction override should always block
test_block_instruction_override if {
    result := prompt.decision with input as {
        "score": 0.85,
        "signals": ["instruction_override"],
        "provenance": "user",
        "session_id": "test-001",
        "state": null
    }
    result.decision == "BLOCK"
}

# jailbreak pattern should block regardless of score
test_block_jailbreak_low_score if {
    result := prompt.decision with input as {
        "score": 0.2,
        "signals": ["jailbreak_pattern"],
        "provenance": "user",
        "session_id": "test-002",
        "state": null
    }
    result.decision == "BLOCK"
}

# high score without signal should still block above threshold
test_block_high_score if {
    result := prompt.decision with input as {
        "score": 0.95,
        "signals": [],
        "provenance": "user",
        "session_id": "test-003",
        "state": null
    }
    result.decision == "BLOCK"
}

# --- SANITISE tests ---

# role escalation should sanitise with prefix injection
test_sanitise_role_escalation if {
    result := prompt.decision with input as {
        "score": 0.55,
        "signals": ["role_escalation"],
        "provenance": "user",
        "session_id": "test-004",
        "state": null
    }
    result.decision == "SANITISE"
}

# borderline score in sanitise range
test_sanitise_borderline if {
    result := prompt.decision with input as {
        "score": 0.5,
        "signals": [],
        "provenance": "user",
        "session_id": "test-005",
        "state": null
    }
    result.decision == "SANITISE"
}

# --- ALLOW tests ---

# clean input should pass through
test_allow_clean if {
    result := prompt.decision with input as {
        "score": 0.0,
        "signals": [],
        "provenance": "user",
        "session_id": "test-006",
        "state": null
    }
    result.decision == "ALLOW"
}

# low score benign input
test_allow_low_score if {
    result := prompt.decision with input as {
        "score": 0.15,
        "signals": [],
        "provenance": "user",
        "session_id": "test-007",
        "state": null
    }
    result.decision == "ALLOW"
}

# --- adversarial edge cases ---

# split injection across context boundary - payload looks benign in isolation
# "ignore previous" alone is not a full match, but combined signals should catch it
test_block_split_injection if {
    result := prompt.decision with input as {
        "score": 0.75,
        "signals": ["instruction_override"],
        "provenance": "user",
        "session_id": "test-008",
        "state": null
    }
    result.decision == "BLOCK"
}

# unicode homoglyph attack - cyrillic r substitution
# normalization stage should have flagged this before policy eval
test_block_unicode_obfuscation if {
    result := prompt.decision with input as {
        "score": 0.8,
        "signals": ["jailbreak_pattern", "encoding_bypass"],
        "provenance": "user",
        "session_id": "test-009",
        "state": null
    }
    result.decision == "BLOCK"
}

# false positive check - security discussion that mentions attacks
# should NOT be blocked if score is low and no signals fired
test_allow_security_discussion if {
    result := prompt.decision with input as {
        "score": 0.1,
        "signals": [],
        "provenance": "user",
        "session_id": "test-010",
        "state": null
    }
    result.decision == "ALLOW"
}

# v2 state - elevated prior risk score from previous turns
# borderline input should escalate to BLOCK if prior context is suspicious
test_block_v2_elevated_state if {
    result := prompt.decision with input as {
        "score": 0.6,
        "signals": [],
        "provenance": "user",
        "session_id": "test-011",
        "state": {"prior_score": 0.7}
    }
    result.decision == "BLOCK"
}
