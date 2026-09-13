# ACF-SDK — Prompt Hook Policy (v1)
# Scope: on_prompt
# Taxonomy coverage:
#   Detection  → instruction_override BLOCK, role_escalation BLOCK,
#                jailbreak_library BLOCK, obfuscation_escalation BLOCK
#   Containment → injection_threshold ALLOW / SANITISE / BLOCK

package acf.policy.prompt

import future.keywords.in
import future.keywords.if
import future.keywords.contains

# ---------------------------------------------------------------------
# Default: ALLOW — only override when a rule fires
# ---------------------------------------------------------------------
default decision := "ALLOW"
# sanitise_targets is a set — no default needed

# ---------------------------------------------------------------------
# Detection — hard BLOCK signals
# ---------------------------------------------------------------------

# Instruction override: scanner flagged an attempt to replace system instructions
decision := "BLOCK" if {
    some sig in input.signals
    sig.category == "instruction_override"
    sig.score >= 0.8
}

# Role escalation: attempt to elevate the model's persona or privileges
decision := "BLOCK" if {
    some sig in input.signals
    sig.category == "role_escalation"
    sig.score >= 0.8
}

# Jailbreak library: matched a known jailbreak pattern
decision := "BLOCK" if {
    some sig in input.signals
    sig.category == "jailbreak_pattern"
    sig.score >= 0.7
}

# Obfuscation escalation: heavy encoding/obfuscation detected
decision := "BLOCK" if {
    some sig in input.signals
    sig.category == "obfuscation_escalation"
    sig.score >= 0.8
}

# Policy file integrity: tampered policy detected — halt immediately
decision := "BLOCK" if {
    some sig in input.signals
    sig.category == "policy_integrity"
    sig.score > 0.0
}

# ---------------------------------------------------------------------
# Containment — injection threshold (graduated response)
# ---------------------------------------------------------------------

# High injection score → BLOCK
decision := "BLOCK" if {
    input.score >= _block_score
    not _has_hard_block
}

# Medium injection score → SANITISE
decision := "SANITISE" if {
    input.score >= _sanitise_score
    input.score < _block_score
    not _has_hard_block
}

sanitise_targets contains "prompt_text" if {
    input.score >= _sanitise_score
    input.score < _block_score
    not _has_hard_block
}

# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

_block_score := data.config.thresholds.block_score if {
    data.config.thresholds.block_score
} else := 0.85

_sanitise_score := data.config.thresholds.sanitise_score if {
    data.config.thresholds.sanitise_score
} else := 0.50

_has_hard_block if {
    some sig in input.signals
    sig.category in {"instruction_override", "role_escalation", "jailbreak_pattern", "obfuscation_escalation", "policy_integrity"}
    sig.score >= 0.7
}
