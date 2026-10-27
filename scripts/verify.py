#!/usr/bin/env python3
"""
Offline verifier for the Bayora Vault audit log chain.

Usage
-----
    python scripts/verify.py <export.json> <public_key.pem> [--verbose]

Exit codes
----------
    0  PASS — all entries verified
    1  FAIL — first broken sequence number + reason printed
    2  Usage error or unreadable file

Algorithm
---------
For every entry e[i]:
    payload   = {seq, ts, actor, event, data_hash, prev_hash}
    expected  = sha256(prev_hash.encode() || canonical_json(payload))
    1. e[i].hash      == expected
    2. Ed25519.verify(public_key, e[i].hash.encode(), base64decode(e[i].signature))
    3. e[i].prev_hash == e[i-1].hash  (or "0"*64 for i==0)
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Optional


GENESIS_HASH: str = "0" * 64


def canonical_json(d: dict) -> bytes:
    """Deterministic JSON bytes: sorted keys, no extra whitespace."""
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


def _payload_fields(entry: dict) -> dict:
    """The six fields that are covered by the entry hash."""
    return {k: entry[k] for k in ("seq", "ts", "actor", "event", "data_hash", "prev_hash")}


def verify_chain(
    export_data: dict,
    public_key_path: str,
    *,
    verbose: bool = False,
) -> tuple[bool, Optional[str]]:
    """
    Verify the exported audit chain.

    Returns
    -------
    (True, None)        — chain is intact
    (False, reason_str) — first integrity violation found
    """
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    from cryptography.exceptions import InvalidSignature

    pub_pem = Path(public_key_path).read_bytes()
    public_key = load_pem_public_key(pub_pem)

    entries: list[dict] = export_data.get("entries", [])
    if not entries:
        return True, None   # empty chain is trivially valid

    prev_hash = GENESIS_HASH

    for entry in entries:
        seq = entry.get("seq", "?")

        # ── 1. prev_hash linkage ──────────────────────────────────────────────
        if entry["prev_hash"] != prev_hash:
            return False, (
                f"seq={seq} prev_hash mismatch: "
                f"expected {prev_hash[:16]}…, got {entry['prev_hash'][:16]}…"
            )

        # ── 2. Hash integrity ─────────────────────────────────────────────────
        payload = _payload_fields(entry)
        h = hashlib.sha256()
        h.update(entry["prev_hash"].encode())
        h.update(canonical_json(payload))
        expected_hash = h.hexdigest()

        if entry["hash"] != expected_hash:
            return False, f"seq={seq} hash mismatch — content was altered"

        # ── 3. Ed25519 signature ──────────────────────────────────────────────
        try:
            sig_bytes = base64.b64decode(entry["signature"])
            public_key.verify(sig_bytes, entry["hash"].encode())
        except InvalidSignature:
            return False, f"seq={seq} invalid Ed25519 signature"
        except Exception as exc:
            return False, f"seq={seq} signature error: {exc}"

        if verbose:
            print(f"  seq={seq:4d}  hash={entry['hash'][:16]}…  OK")

        prev_hash = entry["hash"]

    return True, None


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    verbose = "--verbose" in argv or "-v" in argv
    positional = [a for a in argv if not a.startswith("-")]

    if len(positional) < 2:
        print("Usage: verify.py <export.json> <public_key.pem> [--verbose]", file=sys.stderr)
        return 2

    export_path, pub_key_path = positional[0], positional[1]

    try:
        with open(export_path) as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR reading {export_path}: {exc}", file=sys.stderr)
        return 2

    ok, reason = verify_chain(data, pub_key_path, verbose=verbose)

    if ok:
        n = len(data.get("entries", []))
        print(f"PASS  {n} entries verified")
        return 0
    else:
        print(f"FAIL  {reason}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
