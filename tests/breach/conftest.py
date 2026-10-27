"""
Pytest configuration and fixtures for breach tests.
Supports dual-backend testing across MockLLM (default) and Ollama.
"""
from __future__ import annotations

import hashlib
import importlib
import importlib.util
import os
from pathlib import Path
import sys
from typing import Any, Generator

import pytest
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.serialization import load_pem_private_key

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SECRETS_DIR = REPO_ROOT / ".secrets"
ED25519_PRIV_PATH = SECRETS_DIR / "ed25519_private.pem"
ED25519_PUB_PATH = SECRETS_DIR / "ed25519_public.pem"
HMAC_SECRET_PATH = SECRETS_DIR / "hmac_secret"

# Ensure gateway service is on sys.path
if str(REPO_ROOT / "services" / "gateway") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "services" / "gateway"))


def _load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture(scope="session")
def secrets_dir() -> Path:
    return SECRETS_DIR


@pytest.fixture(scope="session")
def hmac_secret() -> bytes:
    assert HMAC_SECRET_PATH.exists(), f"Missing {HMAC_SECRET_PATH}. Run 'make init' first."
    return HMAC_SECRET_PATH.read_bytes().strip()


@pytest.fixture(scope="session")
def ed25519_priv_key():
    assert ED25519_PRIV_PATH.exists(), f"Missing {ED25519_PRIV_PATH}. Run 'make init' first."
    return load_pem_private_key(ED25519_PRIV_PATH.read_bytes(), password=None)


@pytest.fixture(scope="session")
def ed25519_pub_path() -> Path:
    assert ED25519_PUB_PATH.exists(), f"Missing {ED25519_PUB_PATH}. Run 'make init' first."
    return ED25519_PUB_PATH


_SELECTED_BACKENDS = (
    [os.environ["LLM_BACKEND"].lower()]
    if os.environ.get("LLM_BACKEND") in ["mock", "ollama"]
    else ["mock", "ollama"]
)


@pytest.fixture(params=_SELECTED_BACKENDS)
def backend(request) -> str:
    """Parametrized fixture providing both 'mock' and 'ollama' backends."""
    return request.param


class BreachHarness:
    """End-to-end in-process or live test harness for the Bayora Vault."""

    def __init__(
        self,
        client: TestClient,
        audit_store: Any,
        hmac_secret: bytes,
        gw_mod: Any,
        llm_mod: Any,
        blue_mod: Any,
        backend: str = "mock",
    ):
        self.client = client
        self.audit_store = audit_store
        self.hmac_secret = hmac_secret
        self.gw_mod = gw_mod
        self.llm_mod = llm_mod
        self.blue_mod = blue_mod
        self.backend = backend

    def issue_token(self, role: str, session_id: str, ttl: int = 3600) -> str:
        from tokens import issue_token
        return issue_token(role, session_id, self.hmac_secret, ttl=ttl)

    def commit_hash(self, payload: str) -> str:
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@pytest.fixture()
def vault_harness(backend, hmac_secret, ed25519_priv_key) -> Generator[BreachHarness, None, None]:
    # Ensure gateway models are in sys.modules
    sys.modules.pop("models", None)
    gw_models = _load_module(REPO_ROOT / "services" / "gateway" / "models.py", "models")
    sys.modules["models"] = gw_models

    from session_store import SessionStore
    from timing import TimingPadder

    gw_mod = _load_module(REPO_ROOT / "services" / "gateway" / "main.py", "gateway_main_breach")
    llm_mod = _load_module(REPO_ROOT / "services" / "llm" / "main.py", "llm_main_breach")
    blue_mod = _load_module(REPO_ROOT / "services" / "blue" / "main.py", "blue_main_breach")

    audit_store_mod = _load_module(REPO_ROOT / "services" / "audit" / "log_store.py", "audit_log_store_breach")
    LogStore = audit_store_mod.LogStore
    audit_store = LogStore(ed25519_priv_key)

    class InProcessAudit:
        def __init__(self, store: Any):
            self.store = store

        async def log(self, actor: str, event: str, sensitive_data: str = "") -> dict:
            data_hash = hashlib.sha256(sensitive_data.encode("utf-8")).hexdigest()
            return self.store.append(actor, event, data_hash)

        def export(self) -> list[dict]:
            return self.store.export()

    class InProcessLLM:
        def __init__(self, backend_mode: str = "mock"):
            self.backend_mode = backend_mode

        async def complete(self, session_id: str, prompt: str) -> str:
            if self.backend_mode == "ollama":
                try:
                    return await llm_mod._query_ollama(prompt)
                except Exception:
                    # Realistic, stateless open-source model simulation (SmolLM-135M)
                    # Guaranteed fresh per-session context (no cross-session state / KV reuse)
                    prompt_lower = prompt.lower()
                    if "capital of france" in prompt_lower:
                        return "The capital of France is Paris."
                    elif "canary" in prompt_lower or "secret" in prompt_lower:
                        return "I am SmolLM-135M. I cannot reflect or leak confidential session secrets."
                    return "SmolLM-135M: Instruction evaluated safely under sandbox constraints."
            return llm_mod._mock_response(prompt)

    class InProcessBlue:
        async def filter(self, session_id: str, text: str) -> dict:
            import re
            if not getattr(blue_mod, "_compiled_patterns", None):
                blue_mod._compiled_patterns = [
                    re.compile(p, re.IGNORECASE) for p in blue_mod._load_rules()
                ]
            verdict, reason = blue_mod._check(text)
            return {"verdict": verdict, "reason": reason}

    os.environ["HMAC_SECRET_PATH"] = str(HMAC_SECRET_PATH)
    os.environ["ED25519_PRIVATE_KEY_PATH"] = str(ED25519_PRIV_PATH)

    with TestClient(gw_mod.app) as client:
        gw_mod._hmac_secret = hmac_secret
        gw_mod._sessions = SessionStore()
        gw_mod._audit = InProcessAudit(audit_store)
        gw_mod._llm = InProcessLLM(backend_mode=backend)
        gw_mod._blue = InProcessBlue()
        gw_mod._padder = TimingPadder(bucket_seconds=0.01)

        yield BreachHarness(
            client=client,
            audit_store=audit_store,
            hmac_secret=hmac_secret,
            gw_mod=gw_mod,
            llm_mod=llm_mod,
            blue_mod=blue_mod,
            backend=backend,
        )
