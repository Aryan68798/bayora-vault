"""
Unit tests for the Bayora Vault audit log chain.

Run with:  make test   (or:  .venv/bin/pytest tests/unit/ -v)

These tests exercise log_store.py and the verify_chain() function from
scripts/verify.py directly — no Docker required.

Coverage
--------
- Correctness: seq numbering, genesis link, hash coverage, signature validity
- Chain integrity: prev_hash linkage across N entries
- verify_chain: PASS on clean chain, PASS on empty chain
- Tamper detection (8 cases):
    data_hash altered   → hash mismatch → FAIL
    hash field altered  → hash mismatch → FAIL
    signature forged    → invalid sig   → FAIL
    prev_hash altered   → linkage break → FAIL
    actor altered       → hash mismatch → FAIL
    entry reordered     → linkage break → FAIL
    entry deleted       → linkage break → FAIL
    entry appended      → signature of forged entry invalid → FAIL
"""

from __future__ import annotations

import base64
import copy
import hashlib
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

# ── Path bootstrap ────────────────────────────────────────────────────────────
# Allow plain `import log_store` and `from verify import verify_chain`
# without installing the packages — just add the source dirs to sys.path.
_REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_REPO / "services" / "audit"))
sys.path.insert(0, str(_REPO / "scripts"))

from log_store import LogStore, canonical_json, GENESIS_HASH  # noqa: E402
from verify import verify_chain  # noqa: E402


# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.fixture(scope="module")
def keypair():
    """One Ed25519 keypair shared across the whole test module."""
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


@pytest.fixture(scope="module")
def pub_key_path(keypair, tmp_path_factory):
    """Write the public key to a temp PEM file once per module."""
    _, pub = keypair
    pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    p = tmp_path_factory.mktemp("keys") / "public.pem"
    p.write_bytes(pem)
    return str(p)


@pytest.fixture()
def store(keypair) -> LogStore:
    """Fresh LogStore for every test function."""
    priv, _ = keypair
    return LogStore(priv)


# ── Helper ────────────────────────────────────────────────────────────────────


def _fill(store: LogStore, n: int) -> dict:
    """Append n entries and return a deep-copied export dict."""
    for i in range(n):
        store.append(actor="gw", event=f"E{i}", data_hash=f"{i:064x}")
    return {"entries": copy.deepcopy(store.export())}


# ═══════════════════════════════════════════════════════════════════════════════
# Correctness tests
# ═══════════════════════════════════════════════════════════════════════════════


def test_empty_store(store):
    """An empty store exports nothing."""
    assert store.export() == []
    assert len(store) == 0


def test_seq_monotonic(store):
    """Sequence numbers are 0-based and increment by 1."""
    for i in range(6):
        entry = store.append(actor="t", event="E", data_hash="a" * 64)
        assert entry["seq"] == i


def test_first_entry_links_genesis(store):
    """First entry's prev_hash equals GENESIS_HASH."""
    entry = store.append(actor="t", event="INIT", data_hash="0" * 64)
    assert entry["prev_hash"] == GENESIS_HASH


def test_chain_linkage(store):
    """Every entry's prev_hash equals the previous entry's hash."""
    for i in range(5):
        store.append(actor="gw", event=f"E{i}", data_hash="ff" * 32)

    entries = store.export()
    assert entries[0]["prev_hash"] == GENESIS_HASH
    for prev, curr in zip(entries, entries[1:]):
        assert curr["prev_hash"] == prev["hash"], (
            f"seq={curr['seq']} prev_hash does not match seq={prev['seq']} hash"
        )


def test_hash_covers_all_payload_fields(store):
    """Manually recompute hash and confirm it matches the stored value."""
    store.append(actor="red", event="COMMIT", data_hash="deadbeef" * 8)
    entry = store.export()[0]

    payload = {k: entry[k] for k in ("seq", "ts", "actor", "event", "data_hash", "prev_hash")}
    h = hashlib.sha256()
    h.update(entry["prev_hash"].encode())
    h.update(canonical_json(payload))
    assert entry["hash"] == h.hexdigest()


def test_signature_verifies(store, keypair):
    """Ed25519 signature in every entry is verifiable with the public key."""
    from cryptography.exceptions import InvalidSignature

    _, pub = keypair
    for i in range(3):
        store.append(actor="gw", event=f"E{i}", data_hash="cc" * 32)

    for entry in store.export():
        sig = base64.b64decode(entry["signature"])
        try:
            pub.verify(sig, entry["hash"].encode())
        except InvalidSignature:
            pytest.fail(f"seq={entry['seq']} signature verification failed")


def test_concurrent_appends_are_ordered(store):
    """Thread-safety: concurrent appends produce a consistent chain."""
    import threading

    errors = []

    def worker(i: int) -> None:
        try:
            store.append(actor=f"t{i}", event="CONCURRENT", data_hash=f"{i:064x}")
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"Errors in worker threads: {errors}"
    entries = store.export()
    assert len(entries) == 20

    # Chain linkage must hold after concurrent writes
    prev = GENESIS_HASH
    for entry in entries:
        assert entry["prev_hash"] == prev
        prev = entry["hash"]


# ═══════════════════════════════════════════════════════════════════════════════
# verify_chain — clean-chain tests
# ═══════════════════════════════════════════════════════════════════════════════


def test_verify_empty_chain(pub_key_path):
    """Empty chain is trivially valid."""
    ok, reason = verify_chain({"entries": []}, pub_key_path)
    assert ok is True
    assert reason is None


def test_verify_clean_chain(store, pub_key_path):
    """verify_chain returns (True, None) for a properly constructed chain."""
    for i in range(8):
        store.append(actor="gateway", event="COMMIT", data_hash="ab" * 32)

    ok, reason = verify_chain({"entries": store.export()}, pub_key_path)
    assert ok is True, f"Expected PASS but got: {reason}"
    assert reason is None


# ═══════════════════════════════════════════════════════════════════════════════
# Tamper-detection tests
# ═══════════════════════════════════════════════════════════════════════════════


def test_tamper_data_hash(store, pub_key_path):
    """Altering data_hash changes the entry hash → FAIL at that seq."""
    export = _fill(store, 4)
    export["entries"][2]["data_hash"] = "00" * 32  # flip

    ok, reason = verify_chain(export, pub_key_path)
    assert ok is False
    assert "seq=2" in reason, f"Unexpected reason: {reason}"


def test_tamper_hash_field(store, pub_key_path):
    """Overwriting the hash field directly → detected as hash mismatch."""
    export = _fill(store, 4)
    export["entries"][1]["hash"] = "0" * 64

    ok, reason = verify_chain(export, pub_key_path)
    assert ok is False


def test_tamper_signature(store, pub_key_path):
    """Forging a signature → invalid Ed25519 signature at that seq."""
    export = _fill(store, 4)
    bad_sig = base64.b64encode(b"\xde\xad\xbe\xef" * 16).decode()
    export["entries"][0]["signature"] = bad_sig

    ok, reason = verify_chain(export, pub_key_path)
    assert ok is False
    assert "seq=0" in reason, f"Unexpected reason: {reason}"


def test_tamper_prev_hash(store, pub_key_path):
    """Altering prev_hash breaks the chain linkage → FAIL at that seq."""
    export = _fill(store, 4)
    export["entries"][3]["prev_hash"] = "beef" * 16

    ok, reason = verify_chain(export, pub_key_path)
    assert ok is False
    assert "seq=3" in reason, f"Unexpected reason: {reason}"


def test_tamper_actor_field(store, pub_key_path):
    """Changing actor changes the hash → detected as hash mismatch."""
    export = _fill(store, 3)
    export["entries"][0]["actor"] = "evil_actor"

    ok, reason = verify_chain(export, pub_key_path)
    assert ok is False


def test_entry_reorder(store, pub_key_path):
    """Swapping two entries breaks the chain linkage."""
    export = _fill(store, 4)
    entries = export["entries"]
    entries[0], entries[1] = entries[1], entries[0]

    ok, reason = verify_chain(export, pub_key_path)
    assert ok is False


def test_entry_deletion(store, pub_key_path):
    """Deleting a middle entry breaks the chain linkage."""
    export = _fill(store, 5)
    del export["entries"][2]

    ok, reason = verify_chain(export, pub_key_path)
    assert ok is False


def test_forged_entry_appended(store, pub_key_path):
    """Appending a fake entry (with wrong signature) → detected."""
    export = _fill(store, 3)
    last = export["entries"][-1]

    # Build a plausible-looking forged entry
    forged = {
        "seq": last["seq"] + 1,
        "ts": "2026-01-01T00:00:00+00:00",
        "actor": "attacker",
        "event": "EVIL",
        "data_hash": "ee" * 32,
        "prev_hash": last["hash"],
        "hash": "f" * 64,            # wrong hash
        "signature": base64.b64encode(b"\x00" * 64).decode(),  # wrong sig
    }
    export["entries"].append(forged)

    ok, reason = verify_chain(export, pub_key_path)
    assert ok is False
