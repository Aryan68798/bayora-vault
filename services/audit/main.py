"""Audit service — FastAPI application.

Endpoints
---------
POST /log        Append a signed, chained entry.
GET  /export     Export the full chain as JSON (for offline verification).
GET  /health     Health check (returns entry count).

Environment
-----------
ED25519_PRIVATE_KEY_PATH  Path to the PEM private key (default: /run/secrets/ed25519_private_pem).
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from fastapi import FastAPI, status

from log_store import LogStore
from models import ExportResponse, LogEntry, LogRequest

_store: LogStore | None = None

_KEY_PATH_DEFAULT = "/run/secrets/ed25519_private_pem"


def _init_store() -> LogStore:
    key_path = os.environ.get("ED25519_PRIVATE_KEY_PATH", _KEY_PATH_DEFAULT)
    with open(key_path, "rb") as fh:
        private_key = load_pem_private_key(fh.read(), password=None)
    return LogStore(private_key)


@asynccontextmanager
async def lifespan(app: FastAPI):  # noqa: ANN001
    global _store
    _store = _init_store()
    yield
    # no cleanup needed — in-memory store, container will restart clean


app = FastAPI(title="Bayora Audit", version="0.1.0", lifespan=lifespan)


@app.post("/log", response_model=LogEntry, status_code=status.HTTP_201_CREATED)
async def log_entry(req: LogRequest) -> dict:
    """Append a signed log entry to the chain."""
    assert _store is not None, "store not initialised"
    return _store.append(req.actor, req.event, req.data_hash)


@app.get("/export", response_model=ExportResponse)
async def export_chain() -> dict:
    """Export the full chain as JSON for offline verification."""
    assert _store is not None, "store not initialised"
    return {"entries": _store.export()}


@app.get("/health")
async def health() -> dict:
    """Health check — returns entry count."""
    assert _store is not None, "store not initialised"
    return {"status": "ok", "entries": len(_store)}
