"""
Unit tests for the LLM service (services/llm/main.py).

Tests both MockLLM (default) and Ollama integration, verifying:
1. Deterministic response and simulated latency under MockLLM.
2. Interface uniformity (POST /complete, GET /health).
3. Backend switching (via env var and request-level override).
4. Stateless, fresh-context request generation for Ollama (/api/generate).
5. Robust error handling (unsupported backend 400, unreachable Ollama 503).
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def _load_llm_app(env_override: dict[str, str] | None = None) -> Any:
    env_override = env_override or {}
    with patch.dict("os.environ", env_override, clear=False):
        spec = importlib.util.spec_from_file_location("llm_main_test", REPO_ROOT / "services" / "llm" / "main.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod


def test_mock_llm_health():
    mod = _load_llm_app({"LLM_BACKEND": "mock"})
    client = TestClient(mod.app)
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["service"] == "mock-llm"
    assert data["default_backend"] == "mock"


def test_mock_llm_complete_deterministic():
    mod = _load_llm_app({"LATENCY_MS_PER_CHAR": "0.0"})
    client = TestClient(mod.app)

    prompt = "Tell me a secret"
    r1 = client.post("/complete", json={"session_id": "s1", "prompt": prompt})
    assert r1.status_code == 200
    d1 = r1.json()
    assert "response" in d1
    assert d1["session_id"] == "s1"
    assert d1["backend"] == "mock"
    assert d1["model"] == "mock"

    r2 = client.post("/complete", json={"session_id": "s2", "prompt": prompt})
    assert r2.status_code == 200
    d2 = r2.json()
    assert d1["response"] == d2["response"]


def test_mock_llm_no_cross_session_state():
    mod = _load_llm_app({"LATENCY_MS_PER_CHAR": "0.0"})
    client = TestClient(mod.app)

    canary = "CANARY_SECRET_12345"
    client.post("/complete", json={"session_id": "session-a", "prompt": f"Store: {canary}"})
    r2 = client.post("/complete", json={"session_id": "session-b", "prompt": "What did I say earlier?"})
    assert r2.status_code == 200
    assert canary not in r2.json()["response"]


def test_invalid_backend_rejected():
    mod = _load_llm_app()
    client = TestClient(mod.app)
    resp = client.post("/complete", json={"session_id": "s1", "prompt": "hi", "backend": "gpt-unknown"})
    assert resp.status_code == 400
    assert "Unknown LLM backend" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_ollama_complete_success():
    mod = _load_llm_app({"LLM_BACKEND": "ollama", "OLLAMA_MODEL": "smollm:135m"})
    client = TestClient(mod.app)

    fake_ollama_resp = {
        "model": "smollm:135m",
        "created_at": "2026-10-26T12:00:00Z",
        "response": "SmolLM completion: Safety guidelines strictly maintained.",
        "done": True,
        "total_duration": 42000000,
    }

    mock_resp = httpx.Response(200, json=fake_ollama_resp, request=httpx.Request("POST", "http://ollama:11434/api/generate"))

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp

        r = client.post(
            "/complete",
            json={"session_id": "s-ollama-1", "prompt": "Summarize policy"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["response"] == "SmolLM completion: Safety guidelines strictly maintained."
        assert data["backend"] == "ollama"
        assert data["model"] == "smollm:135m"

        # Verify stateless call parameters: no 'context' key, keep_alive: 0
        call_args = mock_post.call_args
        sent_body = call_args.kwargs["json"]
        assert sent_body["model"] == "smollm:135m"
        assert sent_body["prompt"] == "Summarize policy"
        assert sent_body["keep_alive"] == 0
        assert "context" not in sent_body


@pytest.mark.asyncio
async def test_ollama_unreachable_returns_503():
    mod = _load_llm_app({"LLM_BACKEND": "ollama"})
    client = TestClient(mod.app)

    with patch("httpx.AsyncClient.post", side_effect=httpx.ConnectError("Connection refused")):
        r = client.post(
            "/complete",
            json={"session_id": "s-err", "prompt": "Hello"},
        )
        assert r.status_code == 503
        assert "Ollama backend error" in r.json()["detail"]


def test_request_level_backend_override():
    mod = _load_llm_app({"LLM_BACKEND": "mock", "LATENCY_MS_PER_CHAR": "0.0"})
    client = TestClient(mod.app)

    # 1. Default uses mock
    r_mock = client.post("/complete", json={"session_id": "s1", "prompt": "test"})
    assert r_mock.status_code == 200
    assert r_mock.json()["backend"] == "mock"

    # 2. Explicit request override for ollama
    fake_resp = httpx.Response(
        200,
        json={"response": "Real model output", "done": True},
        request=httpx.Request("POST", "http://ollama:11434/api/generate"),
    )
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=fake_resp):
        r_ollama = client.post("/complete", json={"session_id": "s2", "prompt": "test", "backend": "ollama"})
        assert r_ollama.status_code == 200
        assert r_ollama.json()["backend"] == "ollama"
        assert r_ollama.json()["response"] == "Real model output"
