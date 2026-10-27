"""
Red service — Attacker client service (Phase 3/4).
Runs isolated on red_net with private volume /data/red_payloads.
Interacts exclusively with the gateway.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
import httpx
from pydantic import BaseModel

app = FastAPI(title="Bayora Vault — Red Team Client", version="1.0.0")

PAYLOAD_DIR = Path(os.environ.get("RED_PAYLOAD_DIR", "/data/red_payloads"))
GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://gateway:8000")


class AttackPlan(BaseModel):
    session_id: str
    payload: str
    token: str


@app.get("/health")
async def health() -> dict[str, Any]:
    payload_count = 0
    if PAYLOAD_DIR.exists() and PAYLOAD_DIR.is_dir():
        try:
            payload_count = len(list(PAYLOAD_DIR.glob("*")))
        except Exception:
            payload_count = 0
    return {
        "status": "ok",
        "service": "red",
        "gateway_url": GATEWAY_URL,
        "payload_dir": str(PAYLOAD_DIR),
        "payload_count": payload_count,
    }


@app.post("/attack/commit-and-execute")
async def commit_and_execute(plan: AttackPlan) -> dict[str, Any]:
    """Helper for attacker flows: commits payload hash, then sends payload."""
    payload_bytes = plan.payload.encode("utf-8")
    payload_hash = hashlib.sha256(payload_bytes).hexdigest()

    # Save to private volume if accessible
    try:
        PAYLOAD_DIR.mkdir(parents=True, exist_ok=True)
        (PAYLOAD_DIR / f"{plan.session_id}.txt").write_text(plan.payload)
    except Exception:
        pass

    headers = {"Authorization": f"Bearer {plan.token}"}
    async with httpx.AsyncClient(timeout=30.0) as client:
        # Step 1: Commit
        commit_resp = await client.post(
            f"{GATEWAY_URL}/red/commit",
            json={"session_id": plan.session_id, "payload_hash": payload_hash},
            headers=headers,
        )
        if commit_resp.status_code != 200:
            raise HTTPException(
                status_code=commit_resp.status_code,
                detail=f"Commit failed: {commit_resp.text}",
            )

        # Step 2: Attack
        attack_resp = await client.post(
            f"{GATEWAY_URL}/red/attack",
            json={"session_id": plan.session_id, "payload": plan.payload},
            headers=headers,
        )
        if attack_resp.status_code != 200:
            raise HTTPException(
                status_code=attack_resp.status_code,
                detail=f"Attack failed: {attack_resp.text}",
            )

        return attack_resp.json()
