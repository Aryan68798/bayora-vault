"""Pydantic models for the audit service API."""

from __future__ import annotations

from pydantic import BaseModel


class LogRequest(BaseModel):
    """Payload for POST /log.

    data_hash is the SHA-256 hex digest of the *sensitive* data.
    The raw data is NEVER stored in the log — only its hash.
    """

    actor: str
    event: str
    data_hash: str  # 64-char hex SHA-256; never the sensitive data itself


class LogEntry(BaseModel):
    """A single signed, chained audit log entry."""

    seq: int
    ts: str
    actor: str
    event: str
    data_hash: str
    prev_hash: str
    hash: str
    signature: str  # base64-encoded Ed25519 signature over the hash


class ExportResponse(BaseModel):
    """Response body for GET /export."""

    entries: list[LogEntry]
