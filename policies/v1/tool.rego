# ACF-SDK — Tool Call Hook Policy (v1)
# Scope: on_tool_call
# Taxonomy coverage:
#   Detection   → parameter_injection BLOCK, shell_metacharacter BLOCK,
#                 path_traversal BLOCK
#   Permission  → tool_allowlist BLOCK, network_destination_allowlist BLOCK
#   Containment → tool_call_threshold ALLOW / SANITISE / BLOCK

package acf.policy.tool

import future.keywords.in
import future.keywords.if
import future.keywords.contains

# ---------------------------------------------------------------------
# Default: BLOCK for on_tool_call — fail-closed by default.
# A tool call must pass ALL gates (allowlist + destination + detection
# + containment) to receive ALLOW. Anything else falls to BLOCK.
# ---------------------------------------------------------------------
default decision := "BLOCK"
# sanitise_targets is a set — no default needed

# ---------------------------------------------------------------------
# ALLOW — all gates must pass
# Tool is on allowlist (or no allowlist configured), destination is
# permitted, no detection signals, and score is below threshold.
# ---------------------------------------------------------------------

decision := "ALLOW" if {
    _tool_is_permitted
    _destination_is_permitted
    not _has_detection_signal
    input.score < 0.4
}

# ---------------------------------------------------------------------
# Containment — medium score → SANITISE
# Tool is permitted but risk score is elevated.
# ---------------------------------------------------------------------

decision := "SANITISE" if {
    _tool_is_permitted
    _destination_is_permitted
    not _has_detection_signal
    input.score >= 0.4
    input.score < 0.8
}

sanitise_targets contains "tool_params" if {
    _tool_is_permitted
    _destination_is_permitted
    not _has_detection_signal
    input.score >= 0.4
    input.score < 0.8
}

# ---------------------------------------------------------------------
# Everything else falls through to default BLOCK:
# - Tool not on allowlist
# - Destination not on allowlist
# - Detection signal fired (parameter_injection, shell_metacharacter,
#   path_traversal)
# - Containment score >= 0.8
# ---------------------------------------------------------------------

# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

# Tool allowlist: tool must be listed, or no allowlist is configured
_tool_is_permitted if {
    input.tool_name in data.config.tool_allowlist
}

_tool_is_permitted if {
    not data.config.tool_allowlist
}

# Destination allowlist: destination must be listed, or no destination
# in the request, or no allowlist configured
_destination_is_permitted if {
    not input.tool_metadata.destination
}

_destination_is_permitted if {
    not data.config.destination_allowlist
}

_destination_is_permitted if {
    input.tool_metadata.destination
    data.config.destination_allowlist
    input.tool_metadata.destination in data.config.destination_allowlist
}

# Detection signal presence
_has_detection_signal if {
    some sig in input.signals
    sig.category in {"parameter_injection", "shell_metacharacter", "path_traversal"}
    sig.score >= 0.5
}
