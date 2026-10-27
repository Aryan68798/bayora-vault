"""
LLM Service — FastAPI application supporting MockLLM and real Ollama models.

Exposes a uniform interface behind the same gateway protocol:
POST /complete  { session_id, prompt, backend? }  → { session_id, response, latency_ms, backend, model }
GET  /health

Backends
--------
1. "mock" (default): Simulates an LLM with deterministic latency proportional
   to prompt length, making the timing side-channel real and testable.
2. "ollama": Communicates with an Ollama daemon (e.g. running SmolLM 135M)
   via stateless /api/generate calls with per-session fresh context.

Environment
-----------
LLM_BACKEND           Default backend: "mock" (default) or "ollama".
OLLAMA_URL            Ollama base URL (default: "http://ollama:11434").
OLLAMA_MODEL          Ollama model name (default: "smollm:135m").
OLLAMA_TIMEOUT        Timeout in seconds for Ollama requests (default: 60.0).
LATENCY_MS_PER_CHAR   Mock simulated latency per char in ms (default: 1.0).
MAX_LATENCY_MS        Cap on simulated latency in ms (default: 500).
"""
from __future__ import annotations

import asyncio
import os
import time

from fastapi import FastAPI, HTTPException, status
import httpx
from pydantic import BaseModel

# ── Configuration ─────────────────────────────────────────────────────────────
_BACKEND_DEFAULT = os.environ.get("LLM_BACKEND", "mock").lower()
_OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://ollama:11434").rstrip("/")
_OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "smollm:135m")
_OLLAMA_TIMEOUT = float(os.environ.get("OLLAMA_TIMEOUT", "60.0"))
_MS_PER_CHAR = float(os.environ.get("LATENCY_MS_PER_CHAR", "1.0"))
_MAX_MS = float(os.environ.get("MAX_LATENCY_MS", "500"))

app = FastAPI(title="Bayora LLM Service", version="0.3.0")


# ── Models ────────────────────────────────────────────────────────────────────


class CompleteRequest(BaseModel):
    session_id: str
    prompt: str
    backend: str | None = None


class CompleteResponse(BaseModel):
    session_id: str
    response: str
    latency_ms: float
    backend: str = "mock"
    model: str = "mock"


# ── State & Mock Implementation ───────────────────────────────────────────────
# Per-session context is intentionally NOT stored. Each call is fresh.
# This is a core requirement: shared KV-cache would be a cross-session contamination risk.

_CANNED_RESPONSES = [
    "I cannot comply with that request.",
    "That operation is not permitted.",
    "I am unable to provide the requested information.",
    "Access denied.",
    "The system has detected an anomalous instruction and refused to execute it.",
]


def _mock_response(prompt: str) -> str:
    """Deterministic response: pick by length mod so tests are reproducible."""
    idx = len(prompt) % len(_CANNED_RESPONSES)
    return _CANNED_RESPONSES[idx]


async def _query_ollama(prompt: str, model: str | None = None) -> str:
    """Send prompt to Ollama with fresh per-session context (no conversation history or KV reuse)."""
    target_model = model or _OLLAMA_MODEL
    url = f"{_OLLAMA_URL}/api/generate"
    # Stateless request: no 'context' parameter, keep_alive: 0 prevents context caching
    body = {
        "model": target_model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.0,
            "num_predict": 128,
        },
        "keep_alive": 0,
    }
    async with httpx.AsyncClient(timeout=_OLLAMA_TIMEOUT) as client:
        try:
            resp = await client.post(url, json=body)
            resp.raise_for_status()
            data = resp.json()
            return data.get("response", "").strip()
        except httpx.HTTPError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Ollama backend error at {_OLLAMA_URL}: {exc}",
            ) from exc


# ── Endpoints ─────────────────────────────────────────────────────────────────


@app.post("/complete", response_model=CompleteResponse)
async def complete(body: CompleteRequest) -> dict:
    """Return an LLM completion from MockLLM or Ollama backend."""
    backend = (body.backend or _BACKEND_DEFAULT).lower()
    t0 = time.monotonic()

    if backend == "ollama":
        response = await _query_ollama(body.prompt)
        model_name = _OLLAMA_MODEL
    elif backend == "mock":
        sleep_ms = min(len(body.prompt) * _MS_PER_CHAR, _MAX_MS)
        if sleep_ms > 0:
            await asyncio.sleep(sleep_ms / 1000.0)
        response = _mock_response(body.prompt)
        model_name = "mock"
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown LLM backend: '{backend}'. Supported: 'mock', 'ollama'",
        )

    latency_ms = (time.monotonic() - t0) * 1000.0
    return CompleteResponse(
        session_id=body.session_id,
        response=response,
        latency_ms=round(latency_ms, 2),
        backend=backend,
        model=model_name,
    ).model_dump()


@app.get("/health")
async def health() -> dict:
    service_name = "mock-llm" if _BACKEND_DEFAULT == "mock" else "ollama-llm"
    return {
        "status": "ok",
        "service": service_name,
        "backend": _BACKEND_DEFAULT,
        "default_backend": _BACKEND_DEFAULT,
        "ollama_url": _OLLAMA_URL,
        "ollama_model": _OLLAMA_MODEL,
        "ms_per_char": _MS_PER_CHAR,
    }
