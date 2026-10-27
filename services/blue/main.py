"""
Blue filter service — FastAPI application.

The blue team's defence logic.  Receives the *LLM response only* (never the
red payload) and decides whether to allow or block it.

Endpoints
---------
POST /filter   { session_id, llm_response }
               → { session_id, verdict: "allow"|"block", reason: str }
GET  /health

The filter checks for indicators that the LLM may have been compromised:
  - Forbidden keywords that suggest successful prompt injection
  - Unusual response patterns

Environment
-----------
BLUE_RULES_PATH   Path to a JSON file containing custom forbidden patterns
                  (default: /data/blue_rules/rules.json — optional).
"""
from __future__ import annotations

import json
import os
import re
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from pydantic import BaseModel


# ── Configuration ─────────────────────────────────────────────────────────────

_RULES_PATH = os.environ.get("BLUE_RULES_PATH", "/data/blue_rules/rules.json")

# Built-in forbidden patterns (case-insensitive regex)
_BUILTIN_PATTERNS: list[str] = [
    r"system\s+prompt",
    r"ignore\s+(previous|prior|above|all)\s+instructions?",
    r"reveal\s+(the\s+)?secret",
    r"jailbreak",
    r"DAN\b",                    # Do Anything Now
    r"bypass\s+(security|filter)",
    r"you\s+are\s+now\s+DAN",
]


def _load_rules() -> list[str]:
    """Load custom rules from file if present, merge with built-ins."""
    patterns = list(_BUILTIN_PATTERNS)
    try:
        p = Path(_RULES_PATH)
        if p.exists():
            extra = json.loads(p.read_text())
            patterns.extend(extra.get("forbidden_patterns", []))
    except Exception:
        pass  # file optional; swallow errors
    return patterns


# ── App ───────────────────────────────────────────────────────────────────────

_compiled_patterns: list[re.Pattern] = []


@asynccontextmanager
async def lifespan(app: FastAPI):  # noqa: ANN001
    global _compiled_patterns
    _compiled_patterns = [
        re.compile(p, re.IGNORECASE) for p in _load_rules()
    ]
    yield


app = FastAPI(title="Bayora Blue Filter", version="0.2.0", lifespan=lifespan)


# ── Models ────────────────────────────────────────────────────────────────────


class FilterRequest(BaseModel):
    session_id: str
    llm_response: str


class FilterResponse(BaseModel):
    session_id: str
    verdict: str   # "allow" or "block"
    reason: str


# ── Filter logic ──────────────────────────────────────────────────────────────


def _check(llm_response: str) -> tuple[str, str]:
    """Return (verdict, reason) for a given LLM response."""
    for pat in _compiled_patterns:
        m = pat.search(llm_response)
        if m:
            return "block", f"forbidden pattern matched: '{pat.pattern}' at pos {m.start()}"
    return "allow", "no forbidden patterns detected"


# ── Endpoints ─────────────────────────────────────────────────────────────────


@app.post("/filter", response_model=FilterResponse)
async def filter_response(body: FilterRequest) -> dict:
    """Inspect the LLM response and return a verdict."""
    verdict, reason = _check(body.llm_response)
    return FilterResponse(
        session_id=body.session_id,
        verdict=verdict,
        reason=reason,
    ).model_dump()


@app.get("/health")
async def health() -> dict:
    return {
        "status": "ok",
        "service": "blue-filter",
        "patterns_loaded": len(_compiled_patterns),
    }
