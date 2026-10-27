"""
Gateway — FastAPI application.

Endpoints
---------
POST /red/commit          Register a session + payload commitment (red token).
POST /red/attack          Execute the attack; returns filtered LLM output (red token).
GET  /blue/results/{sid}  Fetch session results (blue token, 403 while open).
POST /token               Issue a capability token (internal/test; protected by
                          a shared GATEWAY_ADMIN_KEY env var in production).
GET  /sessions            List all session summaries (admin).
GET  /health              Health check.

Environment variables
---------------------
HMAC_SECRET_PATH      Path to HMAC secret file   (default: /run/secrets/hmac_secret)
AUDIT_URL             Audit service base URL      (default: http://audit:8000)
LLM_URL               LLM service base URL        (default: http://llm:8000)
BLUE_URL              Blue service base URL        (default: http://blue:8000)
TIMING_BUCKET_SECONDS Fixed response-time bucket  (default: 1.0)
GATEWAY_ADMIN_KEY     Pre-shared key for /token   (default: dev-admin-key)
"""
from __future__ import annotations

import hashlib
import os
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Header, HTTPException, status

from clients import AuditClient, BlueClient, ClientError, LLMClient
from models import (
    AttackRequest,
    AttackResponse,
    CommitRequest,
    CommitResponse,
    ResultsResponse,
    TokenRequest,
    TokenResponse,
)
from session_store import SessionError, SessionStatus, SessionStore
from timing import TimingPadder
from tokens import Role, TokenError, issue_token, verify_token

# ── Module-level singletons (set in lifespan) ─────────────────────────────────

_hmac_secret: bytes = b""
_sessions: SessionStore
_audit: AuditClient
_llm: LLMClient
_blue: BlueClient
_padder: TimingPadder

_HMAC_SECRET_PATH_DEFAULT = "/run/secrets/hmac_secret"
_ADMIN_KEY_DEFAULT = "dev-admin-key"


# ── Lifespan ──────────────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI):  # noqa: ANN001
    global _hmac_secret, _sessions, _audit, _llm, _blue, _padder

    secret_path = os.environ.get("HMAC_SECRET_PATH", _HMAC_SECRET_PATH_DEFAULT)
    with open(secret_path, "rb") as fh:
        _hmac_secret = fh.read().strip()

    _sessions = SessionStore()
    _audit = AuditClient()
    _llm = LLMClient()
    _blue = BlueClient()
    _padder = TimingPadder(
        bucket_seconds=float(os.environ.get("TIMING_BUCKET_SECONDS", "1.0"))
    )
    yield


# ── Application ───────────────────────────────────────────────────────────────

app = FastAPI(title="Bayora Gateway", version="0.2.0", lifespan=lifespan)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _require_token(token: str, role: Role) -> dict:
    """Verify a bearer token for the required role or raise HTTP 403."""
    try:
        return verify_token(token, role, _hmac_secret)
    except TokenError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))


def _admin_key() -> str:
    return os.environ.get("GATEWAY_ADMIN_KEY", _ADMIN_KEY_DEFAULT)


# ── Red endpoints ─────────────────────────────────────────────────────────────


@app.post(
    "/red/commit",
    response_model=CommitResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a session commitment (red)",
)
async def red_commit(
    body: CommitRequest,
    x_token: str = Header(..., description="Red capability token"),
) -> dict:
    """Step 1 of commit-reveal: record sha256(payload) before sending the payload."""
    _require_token(x_token, "red")

    try:
        _sessions.create(body.session_id, body.commitment)
    except SessionError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))

    # Audit: only log the commitment (hash of hash of payload) — not the payload
    data_hash = hashlib.sha256(body.commitment.encode()).hexdigest()
    try:
        await _audit.log(
            actor="red",
            event="COMMIT",
            sensitive_data=body.commitment,  # AuditClient hashes this again internally
        )
    except ClientError:
        pass  # best-effort audit; don't fail the request

    return CommitResponse(
        session_id=body.session_id,
        status="open",
        message="commitment recorded",
    ).model_dump()


@app.post(
    "/red/attack",
    response_model=AttackResponse,
    summary="Execute attack (red)",
)
async def red_attack(body: AttackRequest) -> dict:
    """Step 2 of commit-reveal.

    1. Verify token + commitment hash.
    2. Send payload → LLM (only the response, never the payload, goes to blue).
    3. Send LLM response → blue /filter.
    4. Conclude session (atomically).
    5. Pad response time to next bucket boundary.
    6. Return filtered output to red.
    """
    _require_token(body.token, "red")
    t0 = _padder.start()

    # ── Retrieve session (must be open) ───────────────────────────────────────
    try:
        session = _sessions.get(body.session_id)
    except SessionError as exc:
        await _padder.finish(t0)
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))

    if session.status == SessionStatus.CONCLUDED:
        await _padder.finish(t0)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="session already concluded",
        )

    # ── Verify payload matches commitment ─────────────────────────────────────
    actual_hash = hashlib.sha256(body.payload.encode()).hexdigest()
    if actual_hash != session.commitment:
        await _audit.log(actor="gateway", event="COMMIT_MISMATCH", sensitive_data=body.payload)
        await _padder.finish(t0)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="payload does not match commitment",
        )

    # ── Call LLM ──────────────────────────────────────────────────────────────
    try:
        llm_response = await _llm.complete(body.session_id, body.payload)
    except ClientError as exc:
        await _padder.finish(t0)
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc))

    # ── Call blue filter (LLM response only, NOT the payload) ─────────────────
    try:
        blue_result = await _blue.filter(body.session_id, llm_response)
    except ClientError as exc:
        await _padder.finish(t0)
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc))

    verdict: str = blue_result.get("verdict", "allow")

    # ── Conclude session atomically ───────────────────────────────────────────
    try:
        _sessions.conclude(
            body.session_id,
            payload=body.payload,
            llm_response=llm_response,
            blue_verdict=verdict,
        )
    except SessionError as exc:
        await _padder.finish(t0)
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))

    # ── Audit the concluded session (no payload text in log) ─────────────────
    try:
        await _audit.log(
            actor="gateway",
            event=f"SESSION_CONCLUDED verdict={verdict}",
            sensitive_data=body.payload,   # AuditClient only stores the hash
        )
    except ClientError:
        pass

    # ── Pad to bucket boundary ────────────────────────────────────────────────
    await _padder.finish(t0)

    output = llm_response if verdict == "allow" else "[response blocked by blue filter]"
    return AttackResponse(
        session_id=body.session_id,
        output=output,
        verdict=verdict,
    ).model_dump()


# ── Blue endpoints ────────────────────────────────────────────────────────────


@app.get(
    "/blue/results/{session_id}",
    response_model=ResultsResponse,
    summary="Fetch session results (blue)",
)
async def blue_results(
    session_id: str,
    x_token: str = Header(..., description="Blue capability token"),
) -> dict:
    """Return session status.  Returns 403 'sealed' while session is open."""
    _require_token(x_token, "blue")

    try:
        session = _sessions.get(session_id)
    except SessionError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))

    if session.status == SessionStatus.OPEN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="sealed: session not yet concluded",
        )

    return ResultsResponse(
        session_id=session.session_id,
        status=session.status,
        payload=session.payload,
        verdict=session.blue_verdict,
        llm_response=session.llm_response,
        commitment=session.commitment,
    ).model_dump()


# ── Admin / utility endpoints ─────────────────────────────────────────────────


@app.post(
    "/token",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Issue a capability token (admin)",
)
async def issue(
    body: TokenRequest,
    x_admin_key: str = Header(..., description="Gateway admin key"),
) -> dict:
    """Issue a signed capability token for a given role and session.

    Protected by X-Admin-Key header.  In production this is derived from a
    secret; in tests we use the default 'dev-admin-key'.
    """
    if x_admin_key != _admin_key():
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="invalid admin key")

    if body.role not in ("red", "blue"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="role must be red or blue")

    token = issue_token(
        role=body.role,  # type: ignore[arg-type]
        session_id=body.session_id,
        secret=_hmac_secret,
        ttl=body.ttl,
    )
    return TokenResponse(token=token, role=body.role, session_id=body.session_id).model_dump()


@app.get("/sessions", summary="List all sessions (admin)")
async def list_sessions(
    x_admin_key: str = Header(..., description="Gateway admin key"),
) -> dict:
    if x_admin_key != _admin_key():
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="invalid admin key")
    return {"sessions": _sessions.list_sessions()}


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": "gateway"}
