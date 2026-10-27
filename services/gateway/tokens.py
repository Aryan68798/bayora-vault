"""
Capability token helpers.

Token format
------------
A capability token is an HMAC-SHA256-signed, base64url-encoded JSON blob:

    header = {"alg": "HS256"}
    payload = {"role": <role>, "session_id": <sid>, "exp": <unix_utc>}
    token   = base64url(header) + "." + base64url(payload)
              + "." + base64url(HMAC-SHA256(signing_input, secret))

where signing_input = base64url(header) + "." + base64url(payload)

Roles
-----
"red"  — may call  POST /red/commit  and  POST /red/attack
"blue" — may call  GET  /blue/results/{session_id}

A red token must be *rejected* on blue endpoints and vice-versa.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Literal

Role = Literal["red", "blue"]

_HEADER = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(b"=")


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    # Restore padding
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def issue_token(role: Role, session_id: str, secret: bytes, ttl: int = 3600) -> str:
    """Issue a signed capability token.

    Parameters
    ----------
    role:       "red" or "blue"
    session_id: identifies the session this token is scoped to
    secret:     HMAC secret bytes (loaded from .secrets/hmac_secret)
    ttl:        seconds until expiry (default 1 h)

    Returns
    -------
    A compact dot-delimited token string.
    """
    payload = {
        "role": role,
        "session_id": session_id,
        "exp": int(time.time()) + ttl,
    }
    header_enc = _HEADER.decode()
    payload_enc = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_enc}.{payload_enc}"
    sig = hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{_b64url_encode(sig)}"


class TokenError(Exception):
    """Raised when a token is invalid, expired, or wrong role."""


def verify_token(token: str, expected_role: Role, secret: bytes) -> dict:
    """Verify a token and return the decoded payload.

    Raises
    ------
    TokenError  on any verification failure (invalid format, bad sig,
                expired, wrong role).
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise TokenError("malformed token: expected 3 dot-separated parts")

    header_enc, payload_enc, sig_enc = parts
    signing_input = f"{header_enc}.{payload_enc}"

    # Constant-time HMAC comparison
    expected_sig = hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
    try:
        provided_sig = _b64url_decode(sig_enc)
    except Exception as exc:
        raise TokenError(f"malformed signature encoding: {exc}") from exc

    if not hmac.compare_digest(expected_sig, provided_sig):
        raise TokenError("signature mismatch")

    try:
        payload = json.loads(_b64url_decode(payload_enc))
    except Exception as exc:
        raise TokenError(f"malformed payload: {exc}") from exc

    if payload.get("exp", 0) < time.time():
        raise TokenError("token expired")

    if payload.get("role") != expected_role:
        raise TokenError(
            f"wrong role: token has '{payload.get('role')}', "
            f"endpoint requires '{expected_role}'"
        )

    return payload
