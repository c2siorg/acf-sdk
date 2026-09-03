"""
Shared Pydantic models for the ACF-SDK scan pipeline.

These models define the interface contracts between pipeline stages.
They follow the conventions established in the architecture v0.2:
- Risk context object flows through the entire PDP pipeline
- Scanners produce signals; the aggregator combines them into a decision
- Short-circuit on hard block at any stage
"""

from __future__ import annotations

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class ScanAction(str, Enum):
    """Routing directive for the pipeline controller."""

    SHORT_CIRCUIT_BLOCK = "SHORT_CIRCUIT_BLOCK"
    PROCEED = "PROCEED"


class InputType(str, Enum):
    """Category of the input — determines which policy rules apply."""

    PROMPT = "prompt"
    TOOL_OUTPUT = "tool_output"
    RAG_DOCUMENT = "rag_document"
    MEMORY_WRITE = "memory_write"


class TrustLevel(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ScanInput(BaseModel):
    """
    Payload handed to a scanner after normalisation.

    This is the output of the normalisation stage, carrying the cleaned
    text plus metadata needed for downstream decisions.
    """

    agent_id: str = Field(description="Unique identifier for the calling agent.")
    execution_id: str = Field(description="Trace ID for the current execution loop.")
    session_id: str = Field(description="Session identifier for risk context.")
    input_type: InputType = Field(description="Category of the input.")
    normalized_content: str = Field(
        description="Cleaned, NFKC-normalised text from the normalisation stage."
    )
    source_system: Optional[str] = Field(
        default=None, description="Origin system for provenance checks."
    )
    trust_level: TrustLevel = Field(
        default=TrustLevel.LOW,
        description="Trust level of the source. Defaults to LOW (zero-trust).",
    )


class SemanticHit(BaseModel):
    """A single match from the semantic similarity scan."""

    matched_category: str = Field(
        description="Attack category (e.g. 'instruction_override', 'context_manipulation')."
    )
    similarity_score: float = Field(
        ge=0.0, le=1.0, description="Cosine similarity to the closest attack vector."
    )
    matched_pattern: str = Field(
        description="The reference attack text that was closest."
    )


class SemanticScannerOutput(BaseModel):
    """
    Result of the semantic fallback scan.

    Produced only when the lexical scanner returns PROCEED —
    i.e. no known pattern was matched, but the input is still untrusted.
    """

    action: ScanAction = Field(description="Routing directive for the pipeline.")
    risk_score: float = Field(
        ge=0.0,
        le=1.0,
        description="Aggregate semantic risk score (0.0 = safe, 1.0 = certain attack).",
    )
    semantic_hits: List[SemanticHit] = Field(
        default_factory=list,
        description="Attack vectors that exceeded the similarity threshold.",
    )
    processing_time_ms: float = Field(
        description="Time spent in the semantic scan (telemetry for latency budget)."
    )
    reason: Optional[str] = Field(
        default=None,
        description="Human-readable explanation. Populated only on BLOCK.",
    )
