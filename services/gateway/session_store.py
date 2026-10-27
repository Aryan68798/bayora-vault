"""
Session state machine for the commit-reveal protocol.

States
------
open      — session created; commit has been received; awaiting attack
concluded — attack has been processed; payload is revealed to blue

Transitions
-----------
  (new)  --commit-->  open
  open   --conclude--> concluded

The store is thread-safe via a per-session lock held during conclude so
that double-attack on the same session is detected atomically.
"""
from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class SessionStatus(str, Enum):
    OPEN = "open"
    CONCLUDED = "concluded"


class SessionError(Exception):
    """Raised on invalid session operations."""


@dataclass
class Session:
    session_id: str
    commitment: str  # sha256 hex of the payload
    status: SessionStatus = SessionStatus.OPEN
    payload_hash: str = ""  # set to sha256(payload) on attack; equals commitment
    payload: Optional[str] = None  # revealed to blue upon conclusion
    llm_response: Optional[str] = None
    blue_verdict: Optional[str] = None
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)


class SessionStore:
    """In-memory session registry."""

    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}
        self._global_lock = threading.Lock()

    # ── Public API ────────────────────────────────────────────────────────────

    def create(self, session_id: str, commitment: str) -> Session:
        """Register a new session with an initial commitment.

        Raises SessionError if session_id already exists.
        """
        with self._global_lock:
            if session_id in self._sessions:
                raise SessionError(f"session '{session_id}' already exists")
            # commitment must be a 64-char hex SHA-256
            if len(commitment) != 64 or not _is_hex(commitment):
                raise SessionError("commitment must be a 64-char hex SHA-256 digest")
            s = Session(session_id=session_id, commitment=commitment)
            self._sessions[session_id] = s
            return s

    def get(self, session_id: str) -> Session:
        """Return a session or raise SessionError if not found."""
        try:
            return self._sessions[session_id]
        except KeyError:
            raise SessionError(f"session '{session_id}' not found")

    def conclude(
        self,
        session_id: str,
        payload: str,
        llm_response: str,
        blue_verdict: str,
    ) -> Session:
        """Verify payload against commitment, store results, conclude session.

        Raises
        ------
        SessionError  if session not found, already concluded, or hash mismatch.
        """
        s = self.get(session_id)
        with s._lock:  # per-session lock prevents double-attack race
            if s.status == SessionStatus.CONCLUDED:
                raise SessionError(f"session '{session_id}' already concluded")
            actual_hash = hashlib.sha256(payload.encode()).hexdigest()
            if actual_hash != s.commitment:
                raise SessionError(
                    f"payload hash mismatch: got {actual_hash}, "
                    f"expected {s.commitment}"
                )
            s.payload_hash = actual_hash
            s.payload = payload
            s.llm_response = llm_response
            s.blue_verdict = blue_verdict
            s.status = SessionStatus.CONCLUDED
            return s

    def list_sessions(self) -> list[dict]:
        """Return a summary list of all sessions (no payload text)."""
        with self._global_lock:
            return [
                {
                    "session_id": s.session_id,
                    "status": s.status,
                    "commitment": s.commitment,
                }
                for s in self._sessions.values()
            ]


# ── Helpers ───────────────────────────────────────────────────────────────────


def _is_hex(s: str) -> bool:
    try:
        int(s, 16)
        return True
    except ValueError:
        return False
