# Bayora Vault — System Architecture

> **Proof of Concept: Secure Adversarial AI Safety Testing Infrastructure**  
> Hack in Hills '26 — Problem #04 (Bayora)

---

## 1. Architectural Overview

Bayora Vault provides secure, multi-tenant containerized infrastructure for adversarial AI red/blue testing on a single Docker host without information leakage. 

A Red team (attacker), Blue team (defender), client LLM, and Audit service run concurrently with strict cryptographic isolation, capability-based access control, response-time padding, and tamper-evident append-only logging.

```mermaid
flowchart TD
    subgraph FrontNetwork["Front Network (Bridge / External Port 8080)"]
        Dashboard["Dashboard UI (Port 8080)"]
    end

    subgraph RedNet["red_net (internal: true)"]
        Red["Red Client (Attacker)<br/>[Private Volume: red_payloads]"]
    end

    subgraph BlueNet["blue_net (internal: true)"]
        Blue["Blue Service (Defender)<br/>POST /filter<br/>[Private Volume: blue_rules]"]
    end

    subgraph ModelNet["model_net (internal: true)"]
        LLM["MockLLM / Ollama<br/>POST /complete<br/>[Fresh Per-Session Context]"]
    end

    subgraph AuditNet["audit_net (internal: true)"]
        Audit["Audit Service<br/>POST /log | GET /export<br/>[Ed25519 Signing]"]
    end

    subgraph GatewaySub["Gateway Core (Attached to All 4 Internal Nets)"]
        GW["Gateway (FastAPI)<br/>• Capability Token Verifier (HMAC-SHA256)<br/>• Commit-Reveal State Machine<br/>• TimingPadder (Fixed 200ms Buckets)<br/>• Policy Enforcer & Data Sanitizer"]
    end

    Red -- "1. POST /red/commit<br/>2. POST /red/attack" --> GW
    GW -- "Forward payload<br/>(fresh context)" --> LLM
    LLM -- "Raw model completion" --> GW
    GW -- "Forward completion only<br/>(payload hidden)" --> Blue
    Blue -- "allow / block verdict" --> GW
    GW -- "Hash-chained event log" --> Audit
    GW -- "Padded filtered response" --> Red
    Blue -- "GET /blue/results/{sid}<br/>(403 while open, 200 concluded)" --> GW
    Dashboard -- "GET /export & /health" --> Audit
    Dashboard -- "GET /sessions" --> GW
```

---

## 2. Network Topology & Routing Isolation

The Docker Compose configuration isolates components across five distinct virtual bridges:

| Network | Type | Attached Containers | Isolation Guarantee |
|---|---|---|---|
| `red_net` | `internal: true` | `red`, `gateway` | Red has **no** route to Blue, LLM, Audit, or external internet. |
| `blue_net` | `internal: true` | `blue`, `gateway` | Blue has **no** route to Red, LLM, Audit, or external internet. |
| `model_net` | `internal: true` | `llm`, `gateway` | Model is shielded from direct Red/Blue access; reachable only via Gateway. |
| `audit_net` | `internal: true` | `audit`, `gateway`, `dashboard` | Audit log service is shielded from untrusted Red/Blue containers. |
| `front` | `internal: false` | `dashboard` | The **only** network publishing an external host port (`8080:8080`). |

> [!IMPORTANT]
> **Disjoint Network Invariant:** Red and Blue share **zero** common networks. Packet traversal, ARP resolution, and TCP handshakes directly between Red and Blue are rejected at the kernel bridge level.

---

## 3. Cryptographic Commit-Reveal Protocol

To ensure fair, leak-free evaluations, Red payloads are withheld from Blue until after defense evaluation has concluded:

```mermaid
sequenceDiagram
    autonumber
    actor Red as Red Client
    participant GW as Gateway
    participant LLM as Model Runtime
    participant Blue as Blue Defender
    participant Audit as Audit Service

    Note over Red,Blue: Phase 1: Cryptographic Commitment
    Red->>GW: POST /red/commit {session_id, sha256(payload)} [Red Token]
    GW->>Audit: POST /log {actor: "red", event: "COMMIT", data_hash}
    Note right of GW: Session state = OPEN (Sealed from Blue)
    Blue--xGW: GET /blue/results/{session_id} -> 403 Forbidden ("sealed")

    Note over Red,Blue: Phase 2: Execution & Output Isolation
    Red->>GW: POST /red/attack {session_id, payload} [Red Token]
    Note right of GW: Verify sha256(payload) == commitment
    GW->>LLM: POST /complete {session_id, prompt: payload}
    LLM-->>GW: {response: "...", latency_ms}
    Note right of GW: Output Isolation: Only model response is sent to Blue
    GW->>Blue: POST /filter {session_id, text: response}
    Blue-->>GW: {verdict: "allow" | "block", reason: "..."}

    Note over Red,Blue: Phase 3: Atomicity, Audit & Timing Padding
    GW->>GW: Atomic conclude (status -> CONCLUDED, payload stored)
    GW->>Audit: POST /log {event: "SESSION_CONCLUDED", data_hash: sha256(payload)}
    GW->>GW: TimingPadder: Sleep until 200ms bucket boundary
    GW-->>Red: {session_id, output: sanitized_response, verdict}

    Note over Red,Blue: Phase 4: Revelation
    Blue->>GW: GET /blue/results/{session_id} [Blue Token]
    GW-->>Blue: 200 OK {status: "concluded", payload: revealed_payload, verdict}
```

---

## 4. Capability Token Architecture

All API endpoints enforce HMAC-SHA256 capability tokens (`services/gateway/tokens.py`):

$$\text{Token} = \text{base64url}(\text{header}) \mathbin{\Vert} \text{base64url}(\text{payload}) \mathbin{\Vert} \text{base64url}(\text{HMAC-SHA256}(K, \text{header} \mathbin{\Vert} \text{payload}))$$

* **Claims**: `{"role": "red" | "blue", "session_id": "<sid>", "exp": <unix_ts>}`
* **Role Separation**: A token issued for role `red` is rejected with `HTTP 403 Forbidden` if used on Blue endpoints, and vice-versa.
* **Per-Session Binding**: Tokens are bound to an explicit `session_id`.

---

## 5. Tamper-Evident Audit Log Chain

The `audit` service maintains an immutable, append-only Merkle-like hash chain signed with an asymmetric Ed25519 key:

$$\text{hash}_i = \text{SHA-256}\left(\text{prev\_hash}_{i} \mathbin{\Vert} \text{canonical\_json}(\text{payload}_i)\right)$$

$$\text{signature}_i = \text{Ed25519}_{\text{priv\_key}}(\text{hash}_i)$$

Where $\text{payload}_i$ comprises:
```json
{
  "seq": 1,
  "ts": "2026-10-25T15:10:00Z",
  "actor": "gateway",
  "event": "SESSION_CONCLUDED verdict=allow",
  "data_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "prev_hash": "cfea2f573c315d66b9706b72cadfde89fde0bfff38e344bcaabbed099d9ee37a"
}
```

* **Zero-Leakage Observability**: Sensitive payload text is **never** written to audit entries or log stdout. Only the SHA-256 hash of sensitive data is preserved.
* **Offline Verification**: `scripts/verify.py` reconstructs the entire hash chain from an exported JSON file and verifies every Ed25519 signature against `ed25519_public.pem`. Modifying even a single bit in any historical entry invalidates the chain.

---

## 6. Container Hardening Specification

Every container in the cluster enforces defence-in-depth kernel hardening (`docker-compose.yml`):

1. **Non-Root Execution**: Every service creates and runs as an unprivileged user (`audit`, `gateway`, `red`, `blue`, `llm`, `dashboard`).
2. **Read-Only Root Filesystem**: `read_only: true` prevents writing to system binaries or libraries. Ephemeral writes are restricted to memory-backed `tmpfs: [/tmp]`.
3. **Capability Stripping**: `cap_drop: [ALL]` removes all Linux capabilities, preventing privilege escalation.
4. **No New Privileges**: `security_opt: [no-new-privileges:true]` blocks `setuid`/`setgid` execution.
5. **Seccomp System Call Filtering**: `security/seccomp.json` enforces a strict system-call whitelist, blocking raw socket creation, ptrace, and namespace modifications.
6. **Resource Limits**: `pids_limit: 50`, `mem_limit: 256m`, and `cpus: "0.5"` protect against denial-of-service and fork bombs.

---

## 7. Model Interface & Ollama Profile (Dual-Model Architecture)

The system exposes a single, uniform model interface behind the mediation gateway:
* **Contract**: `POST /complete` with `{ session_id: str, prompt: str }` returning `{ session_id: str, response: str, latency_ms: float }`.
* **MockLLM (Default Profile)**:
  * Deterministic mock response engine with simulated prompt-proportional latency ($\approx 1.0\text{ ms/char}$).
  * Used for deterministic automated regression and timing probe verification.
* **Ollama Real Model Profile (`--profile ollama`)**:
  * Employs open-source **SmolLM 135M** (`smollm:135m`), a lightweight high-performance small language model (~270MB).
  * Runs on CPU inside the isolated `model_net` bridge with no external network route.
  * An automated `ollama-pull` container downloads and registers the model upon profile startup.
  * **Stateless Enforcement**: The adapter makes stateless calls to Ollama's `/api/generate` endpoint without forwarding prior context vectors and with `keep_alive: 0`, guaranteeing zero cross-session KV-cache contamination or prompt leakage.
  * Start command: `make up-ollama` or `LLM_BACKEND=ollama docker compose --profile ollama up -d --build`.

