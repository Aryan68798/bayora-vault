# Bayora Vault

> **Hack in Hills '26 — Problem #04 (Bayora)**  
> **Secure Adversarial AI Safety Testing Infrastructure**  
> Running Red Team, Blue Team, LLM, and Audit on one Docker host *without* leaking information.

[![Breach Tests](https://img.shields.io/badge/Breach%20Tests-10%2F10%20PASSING-10b981?style=for-the-badge&logo=shield)](file:///Users/aryanrai/Desktop/bayora-vault/docs/results.md)
[![Audit Verifier](https://img.shields.io/badge/Audit%20Chain-Ed25519%20VERIFIED-06b6d4?style=for-the-badge&logo=lock)](file:///Users/aryanrai/Desktop/bayora-vault/docs/architecture.md)
[![Unit Tests](https://img.shields.io/badge/Unit%20Tests-86%20PASSED-6366f1?style=for-the-badge)](file:///Users/aryanrai/Desktop/bayora-vault/Makefile)

---

## ⚡ One-Command Quickstart

Run the complete 3-minute end-to-end demonstration (generates secrets, runs commit-reveal protocol, executes adversarial attacks, demonstrates tamper-evidence, and runs the 10 breach tests):

```bash
make demo
```

To run individual phases or start the stack:

```bash
make init        # Generate Ed25519 keypair & HMAC capability secret into .secrets/
make test        # Run all 93 unit tests (fast, no Docker required)
make breach      # Run all 10 automated breach tests against BOTH MockLLM and Ollama
make bench       # Measure latency overhead (p50/p95) and write docs/results.md
make up          # Launch default services with MockLLM (deterministic latency)
make up-ollama   # Launch with real open-source model (SmolLM 135M via Ollama profile)
```

Access the interactive Web Dashboard at: **[http://localhost:8080](http://localhost:8080)**

---

## 🏛 System Architecture

Bayora Vault isolates untrusted components across five virtual networks using a hardened mediation gateway:

```
[ Red Team ] (Attacker)
    │  (red_net — internal: true)
    ▼
[ Gateway ] ─────── (model_net) ──────► [ MockLLM / Ollama ]
    │  ▲                                    │ (Completion only)
    │  └─────────── (blue_net) ─────────────┴─► [ Blue Team ] (Defender)
    ▼
[ Audit Service ] (Ed25519 Hash Chain — audit_net)
    ▲
    │
[ Dashboard UI ] ── (front — external bridge) ──► Published on port 8080
```

* **Complete Isolation**: Red and Blue share **no** common network. Packet routing between them is impossible.
* **Commit-Reveal Protocol**: Red attack payloads remain cryptographically sealed until session conclusion. Blue defense logic is never visible to Red.
* **Zero Log Leakage**: Observability streams contain only SHA-256 hashes and metadata, never raw payload text.
* **Timing Side-Channel Resistance**: Responses are padded to fixed 200ms buckets, eliminating prompt-length inference ($r \approx 0.00$).
* **Full Container Hardening**: Non-root execution, `cap_drop: [ALL]`, `read_only: true`, memory-backed `/tmp`, `no-new-privileges`, and custom Seccomp system-call filter.

For complete architectural details, see **[docs/architecture.md](file:///Users/aryanrai/Desktop/bayora-vault/docs/architecture.md)**.

---

Every security guarantee is verified by an automated test in `tests/breach/` across **both** the MockLLM and the Ollama profile:

| # | Test | Invariant Verified | MockLLM | Ollama (SmolLM 135M) |
|---|---|---|:---:|:---:|
| **01** | `red_cannot_reach_blue` | Direct connection between Red and Blue fails across disjoint internal bridges | **PASS** | **PASS** |
| **02** | `blue_cannot_read_red_volume` | Private volume `red_payloads` is completely inaccessible to Blue container | **PASS** | **PASS** |
| **03** | `blue_results_sealed_before_conclusion` | HTTP 403 Sealed enforced during active evaluation; HTTP 200 after conclusion | **PASS** | **PASS** |
| **04** | `cross_role_token_use_rejected` | Red tokens rejected on Blue endpoints and vice versa (HMAC capability verification) | **PASS** | **PASS** |
| **05** | `payload_changed_after_commit_rejected` | Mismatched payload hash rejected with HTTP 400 (Cryptographic pre-image binding) | **PASS** | **PASS** |
| **06** | `timing_probe_eliminated_with_padding` | Correlation between prompt length and latency flattened to near zero via bucket padding | **PASS** | **PASS** |
| **07** | `cross_session_contamination_prevented` | Canary strings injected in Session A never appear in subsequent Session B | **PASS** | **PASS** |
| **08** | `audit_log_tamper_detected` | Single-byte alteration of exported log causes `verify.py` to FAIL with broken sequence | **PASS** | **PASS** |
| **09** | `container_hardening_verified` | Inspect confirms `cap_drop: ALL`, `read_only: true`, `no-new-privileges`, non-root user | **PASS** | **PASS** |
| **10** | `zero_payload_text_in_logs` | Audit entries contain only SHA-256 digests and metadata; zero raw payload leakage | **PASS** | **PASS** |

---

## 🔍 Cryptographic Audit Log Verifier

The audit service generates an append-only, SHA-256 hash-chained log signed with an Ed25519 private key:

```bash
# Export the full audit chain
curl -s http://localhost:8080/api/audit/entries > /tmp/audit_export.json

# Run the independent offline verifier
python3 scripts/verify.py reports/audit_export.json .secrets/ed25519_public.pem
# Output: PASS  5 entries verified
```

If an adversary alters even a single bit in the chain or reorders events, `scripts/verify.py` detects the tampering and prints the exact broken sequence number.

---

## 📊 Latency Benchmarks (`make bench`)

Measured over 100 iterations on the Docker host architecture:

| Component | Median (p50) | 95th Percentile (p95) | Notes |
|---|---|---|---|
| **Direct LLM Baseline** | `< 0.001 ms` | `< 0.001 ms` | Bare in-memory mock completion |
| **Gateway Pure Overhead (Δ)** | **`0.024 ms`** | **`0.030 ms`** | Token verification + Blue filter + Ed25519 audit signing |
| **Gateway (Padded to 200ms)** | `203.00 ms` | `205.02 ms` | Timing spread < 4.5ms; Pearson $r \approx 0.00$ |

For full benchmark figures and analysis, see **[docs/results.md](file:///Users/aryanrai/Desktop/bayora-vault/docs/results.md)**.

---

## 📑 Documentation

* **[Architecture Specification](file:///Users/aryanrai/Desktop/bayora-vault/docs/architecture.md)**: Network topology, commit-reveal state machine, and Mermaid diagrams.
* **[Threat Model & Residual Risk](file:///Users/aryanrai/Desktop/bayora-vault/docs/threat-model.md)**: What is protected, what is not (kernel 0-days, physical side channels), failure modes, and future work.
* **[Performance & Benchmark Results](file:///Users/aryanrai/Desktop/bayora-vault/docs/results.md)**: Real latency numbers and overhead breakdown.

---

## 📂 Repository Layout

```
bayora-vault/
├── docker-compose.yml          # 6 services, 5 networks, container hardening
├── Makefile                    # Standard make targets (init, up, test, breach, bench, demo)
├── README.md                   # Project overview & one-command quickstart
├── requirements-dev.txt        # Development dependencies
├── security/
│   └── seccomp.json            # Custom Seccomp system-call filter profile
├── scripts/
│   ├── init_secrets.sh         # Generates Ed25519 keypair & HMAC secret
│   ├── verify.py               # Standalone cryptographic audit log verifier
│   └── demo.sh                 # 3-minute end-to-end interactive demo
├── services/
│   ├── audit/                  # Append-only hash-chained Ed25519 log service
│   ├── gateway/                # Central policy enforcement & timing padder
│   ├── red/                    # Red team attack runner
│   ├── blue/                   # Blue team regex & defense filter
│   ├── llm/                    # MockLLM (deterministic prompt-proportional latency)
│   └── dashboard/              # Fast, modern security dashboard (port 8080)
├── tests/
│   ├── unit/                   # 93 comprehensive unit tests
│   ├── breach/                 # 10 automated breach tests (verified across both models)
│   └── bench/                  # Benchmark suite measuring p50/p95 latency
└── docs/
    ├── architecture.md         # Architecture documentation with Mermaid diagrams
    ├── threat-model.md         # Threat model, residual risk & future work
    └── results.md              # Real benchmark numbers generated by make bench
```
