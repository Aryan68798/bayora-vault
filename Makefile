.PHONY: all help init up up-ollama down test breach bench demo logs clean

COMPOSE = docker compose
PYTHON  = python3
VENV    = .venv
PY      = $(VENV)/bin/python
PYTEST  = $(VENV)/bin/pytest

all: help

help:
	@printf "\nBayora Vault — make targets\n"
	@printf "  make init        Generate Ed25519 keypair + HMAC secret into .secrets/\n"
	@printf "  make up          Build and start default services (MockLLM)\n"
	@printf "  make up-ollama   Start with real open-source model (SmolLM via Ollama profile)\n"
	@printf "  make down        Stop containers\n"
	@printf "  make test        Run unit tests  (no Docker required)\n"
	@printf "  make breach      Run all 10 breach tests  (requires: make up)\n"
	@printf "  make bench       Measure gateway latency overhead\n"
	@printf "  make demo        End-to-end demonstration script\n"
	@printf "  make logs        Tail container logs\n"
	@printf "  make clean       Remove containers, images, and venv\n\n"

# ── Virtualenv ────────────────────────────────────────────────────────────────

$(VENV): requirements-dev.txt
	$(PYTHON) -m venv $(VENV)
	$(PY) -m pip install --quiet --upgrade pip
	$(PY) -m pip install --quiet -r requirements-dev.txt
	@echo "==> Virtualenv ready: $(VENV)/"

# ── Secrets ───────────────────────────────────────────────────────────────────

init: $(VENV)
	@bash scripts/init_secrets.sh

# ── Docker ────────────────────────────────────────────────────────────────────

up:
	@test -f .secrets/ed25519_private.pem || \
		(echo "ERROR: run 'make init' first to generate secrets"; exit 1)
	$(COMPOSE) up -d --build

up-ollama:
	@test -f .secrets/ed25519_private.pem || \
		(echo "ERROR: run 'make init' first to generate secrets"; exit 1)
	LLM_BACKEND=ollama $(COMPOSE) --profile ollama up -d --build

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f

# ── Tests ─────────────────────────────────────────────────────────────────────

test: $(VENV)
	$(PYTEST) tests/unit/ -v

breach: $(VENV)
	@test -f .secrets/ed25519_private.pem || \
		(echo "ERROR: run 'make init && make up' first"; exit 1)
	$(PYTEST) tests/breach/ -v -s --tb=short

bench: $(VENV)
	$(PY) tests/bench/bench.py

# ── Demo ──────────────────────────────────────────────────────────────────────

demo:
	@bash scripts/demo.sh

# ── Cleanup ───────────────────────────────────────────────────────────────────

clean:
	-$(COMPOSE) down -v --rmi local 2>/dev/null || true
	rm -rf $(VENV)
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
