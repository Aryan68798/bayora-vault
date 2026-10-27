"""
Append-only, hash-chained, Ed25519-signed audit log store.

Chain invariant
---------------
For every entry e[i]:

    payload[i] = {seq, ts, actor, event, data_hash, prev_hash}

    e[i].hash = sha256(
        e[i].prev_hash.encode()        # hex of previous hash, UTF-8 encoded
        || canonical_json(payload[i])  # sorted keys, no whitespace
    ).hexdigest()

    e[i].signature = Ed25519.sign(e[i].hash.encode())

    e[i].prev_hash = e[i-1].hash   (GENESIS_HASH = "0"*64 for i == 0)

The store is thread-safe. Entries are immutable once appended.
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
from datetime import datetime, timezone
from typing import List

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


#: Genesis prev_hash: 64 hex zeros, used for the very first entry.
GENESIS_HASH: str = "0" * 64


def canonical_json(d: dict) -> bytes:
    """Produce deterministic JSON bytes (sorted keys, no whitespace)."""
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


class LogStore:
    """Thread-safe, append-only audit log with hash chain and Ed25519 signatures."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key
        self._entries: List[dict] = []
        self._lock = threading.Lock()

    # ── Public API ────────────────────────────────────────────────────────────

    def append(self, actor: str, event: str, data_hash: str) -> dict:
        """Append a signed, chained entry and return it."""
        with self._lock:
            return self._build_and_append(actor, event, data_hash)

    def export(self) -> List[dict]:
        """Return a shallow-copy list of all entries (safe to serialise)."""
        with self._lock:
            return list(self._entries)

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _build_and_append(self, actor: str, event: str, data_hash: str) -> dict:
        seq = len(self._entries)
        ts = datetime.now(timezone.utc).isoformat()
        prev_hash = self._entries[-1]["hash"] if self._entries else GENESIS_HASH

        payload: dict = {
            "seq": seq,
            "ts": ts,
            "actor": actor,
            "event": event,
            "data_hash": data_hash,
            "prev_hash": prev_hash,
        }

        # hash = sha256(prev_hash_bytes || canonical_json(payload))
        h = hashlib.sha256()
        h.update(prev_hash.encode())
        h.update(canonical_json(payload))
        entry_hash = h.hexdigest()

        # signature = Ed25519(private_key).sign(hash_hex.encode())
        raw_sig = self._private_key.sign(entry_hash.encode())
        signature = base64.b64encode(raw_sig).decode()

        entry = {**payload, "hash": entry_hash, "signature": signature}
        self._entries.append(entry)
        return entry
