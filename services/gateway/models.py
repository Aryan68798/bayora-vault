"""
Pydantic models for the gateway API.
"""
from __future__ import annotations

from pydantic import BaseModel, field_validator


# ── Red endpoints ─────────────────────────────────────────────────────────────


class CommitRequest(BaseModel):
    """Body for POST /red/commit."""

    session_id: str
    commitment: str  # sha256(payload) hex, 64 chars

    @field_validator("commitment")
    @classmethod
    def commitment_is_hex64(cls, v: str) -> str:
        if len(v) != 64:
            raise ValueError("commitment must be exactly 64 hex characters")
        try:
            int(v, 16)
        except ValueError:
            raise ValueError("commitment must be hexadecimal")
        return v.lower()


class CommitResponse(BaseModel):
    session_id: str
    status: str
    message: str


class AttackRequest(BaseModel):
    """Body for POST /red/attack."""

    session_id: str
    payload: str   # the actual attack prompt
    token: str     # red capability token


class AttackResponse(BaseModel):
    session_id: str
    output: str    # the (potentially filtered) LLM output returned to red
    verdict: str   # "allow" or "block"


# ── Blue endpoints ────────────────────────────────────────────────────────────


class ResultsResponse(BaseModel):
    session_id: str
    status: str         # "open" | "concluded"
    payload: str | None = None  # revealed upon conclusion
    verdict: str | None = None
    llm_response: str | None = None
    commitment: str | None = None


# ── Token issuance (internal / test helper) ───────────────────────────────────


class TokenRequest(BaseModel):
    role: str        # "red" | "blue"
    session_id: str
    ttl: int = 3600


class TokenResponse(BaseModel):
    token: str
    role: str
    session_id: str
