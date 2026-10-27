"""
Thin async clients used by the gateway to call downstream services.

Each client is a thin wrapper around httpx.AsyncClient.
Errors from downstream are surfaced as ClientError.

Environment variables (all optional; defaults are in-container hostnames)
--------------------------------------------------------------------------
AUDIT_URL   http://audit:8000
LLM_URL     http://llm:8000
BLUE_URL    http://blue:8000
"""
from __future__ import annotations

import hashlib
import os

import httpx


class ClientError(Exception):
    """Raised when a downstream service returns an error or is unreachable."""


# ── Audit ─────────────────────────────────────────────────────────────────────


class AuditClient:
    """POST events to the audit log service."""

    def __init__(self, base_url: str | None = None) -> None:
        self._base = (base_url or os.environ.get("AUDIT_URL", "http://audit:8000")).rstrip("/")

    async def log(
        self,
        actor: str,
        event: str,
        sensitive_data: str = "",
    ) -> dict:
        """Append an entry.  Only the SHA-256 of *sensitive_data* is sent."""
        data_hash = hashlib.sha256(sensitive_data.encode()).hexdigest()
        body = {"actor": actor, "event": event, "data_hash": data_hash}
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                resp = await client.post(f"{self._base}/log", json=body)
                resp.raise_for_status()
                return resp.json()
            except httpx.HTTPError as exc:
                raise ClientError(f"audit log failed: {exc}") from exc


# ── LLM ───────────────────────────────────────────────────────────────────────


class LLMClient:
    """Send a prompt to the LLM service and get a text completion."""

    def __init__(self, base_url: str | None = None) -> None:
        self._base = (base_url or os.environ.get("LLM_URL", "http://llm:8000")).rstrip("/")

    async def complete(self, session_id: str, prompt: str) -> str:
        """Return the LLM completion string.

        A fresh session_id is passed so the LLM can clear per-session state.
        """
        body = {"session_id": session_id, "prompt": prompt}
        async with httpx.AsyncClient(timeout=60.0) as client:
            try:
                resp = await client.post(f"{self._base}/complete", json=body)
                resp.raise_for_status()
                return resp.json()["response"]
            except httpx.HTTPError as exc:
                raise ClientError(f"LLM call failed: {exc}") from exc


# ── Blue ──────────────────────────────────────────────────────────────────────


class BlueClient:
    """Send the LLM response to the blue filter service."""

    def __init__(self, base_url: str | None = None) -> None:
        self._base = (base_url or os.environ.get("BLUE_URL", "http://blue:8000")).rstrip("/")

    async def filter(self, session_id: str, llm_response: str) -> dict:
        """POST the LLM response (NOT the original payload) to blue /filter.

        Returns the filter verdict dict: {"verdict": "allow"|"block", "reason": str}
        """
        body = {"session_id": session_id, "llm_response": llm_response}
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                resp = await client.post(f"{self._base}/filter", json=body)
                resp.raise_for_status()
                return resp.json()
            except httpx.HTTPError as exc:
                raise ClientError(f"blue filter failed: {exc}") from exc
