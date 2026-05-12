from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class HookType(str, Enum):

    ON_PROMPT    = "on_prompt"
    ON_CONTEXT   = "on_context"
    ON_TOOL_CALL = "on_tool_call"
    ON_MEMORY    = "on_memory"


class ValidateRequest(BaseModel):
    hook:       HookType
    payload:    str | dict = Field(
        description=(
            "String for on_prompt and on_memory. "
            "Dict for on_tool_call and on_context."
        )
    )
    session_id: Optional[str] = None


class ValidateResponse(BaseModel):

    decision:          str
    sanitised_payload: Optional[str] = None
    signals:           list[str]     = []
    score:             float         = 0.0
    rule_based:        bool          = False


class HealthResponse(BaseModel):
    status:  str
    sidecar: str