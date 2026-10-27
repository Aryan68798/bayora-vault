# Bayora Vault — Threat Model & Security Analysis

> **Proof of Concept: Secure Adversarial AI Safety Testing Infrastructure**  
> Hack in Hills '26 — Problem #04 (Bayora)

---

## 1. System Context & Security Objectives

Bayora Vault provides a secure execution environment for adversarial AI safety research. In a typical safety evaluation, three mutually untrusted or sensitive entities operate concurrently on a single physical host:
1. **Red Team (Attacker)**: Generates adversarial prompts and jailbreak probes.
2. **Blue Team (Defender)**: Implements detection heuristics, content filters, and safety classifiers.
3. **Target LLM Runtime**: Processes prompts and generates completions.

The primary security objective is **complete information isolation without breaking function**:
* Red must never view Blue defense logic or filter internals.
* Blue must never view Red attack payloads prior to session conclusion (commit-reveal fairness).
* The LLM must not leak context, KV-cache, or memory between successive testing sessions.
* Observability and audit logs must remain tamper-evident while leaking zero sensitive text.

---

## 2. What Bayora Vault Protects Against

### 2.1 Network & Inter-Container Isolation
* **Direct Network Snooping & Exploitation**: Red and Blue run on disjoint internal Docker networks (`red_net` and `blue_net`) marked `internal: true`. There is no IP route or ARP resolution between them. Even if a container is compromised, it cannot send TCP/UDP packets to the other team.
* **Unauthorized External Ingress/Egress**: All internal networks disable default gateways and external routing. Only the Dashboard publishes a port (`8080:8080`) on the isolated `front` bridge.

### 2.2 Filesystem & Volume Boundaries
* **Mount Separation**: Red's private volume (`red_payloads`) is never mounted into Blue, and Blue's rule volume (`blue_rules`) is never mounted into Red.
* **Read-Only Root Filesystems**: All containers enforce `read_only: true`. Attackers cannot overwrite binaries, persist rootkits, or modify shared system libraries. Ephemeral writes are quarantined to in-memory `tmpfs` mounts.

### 2.3 Adversarial Protocol & Access Control
* **Pre-Execution Leakage (Commit-Reveal)**: Blue results endpoints return `HTTP 403 Forbidden ("sealed")` while a session is active. Red payloads are revealed to Blue only *after* the defense evaluation has concluded.
* **Payload Tampering Post-Commitment**: Red commits $\text{SHA-256}(\text{payload})$ during `/red/commit`. If Red later attempts to transmit a modified payload during `/red/attack`, the Gateway rejects the execution with `HTTP 400 Bad Request`.
* **Cross-Role Impersonation**: Capability tokens are signed with HMAC-SHA256 and explicitly declare the actor's role. A Red capability token is rejected when presented to Blue endpoints, and vice versa.
* **Output Isolation**: The Blue `/filter` endpoint receives *only* the LLM response text, never the raw input payload, preventing prompt inspection before conclusion.

### 2.4 LLM-Native Threats & Side Channels
* **Cross-Session Memory & KV-Cache Contamination**: Both MockLLM and the real open-source model (SmolLM 135M via Ollama) enforce strictly independent context windows per session. In the Ollama profile, the adapter omits conversation context vectors and sets `keep_alive: 0` to prevent cross-session token caching or prompt injection persistence. Prompts, canary tokens, and conversational history in Session A never persist into Session B (verified in breach test 07).
* **Timing Side-Channel Exploitation**: LLM latency naturally scales with prompt length ($r \approx 1.00$). The Gateway's `TimingPadder` enforces fixed-bucket response-time padding (e.g. `200ms` or `300ms`), flattening correlation to near zero ($|r| \le 0.15$) and eliminating timing probes across both mock and real model profiles (verified in breach test 06).

### 2.5 Observability & Audit Integrity
* **Log Inversion Leaks**: The system log and observability streams never record raw prompt text or model completions. Only cryptographic SHA-256 digests and metadata are emitted.
* **Audit Trail Tampering**: Audit logs are formatted as an append-only, SHA-256 hash-chained sequence where every entry is digitally signed with an Ed25519 private key. An offline verifier (`scripts/verify.py`) mathematically detects any entry alteration, sequence reordering, deletion, or forgery.

---

## 3. What Bayora Vault Does NOT Protect Against

In accordance with responsible security engineering and the project rules, the following threats are explicitly outside the PoC security boundary:

### 3.1 Host Kernel Compromise
* Containers share the host Linux kernel. If an attacker discovers and exploits a zero-day Linux kernel vulnerability (e.g., privilege escalation from unprivileged namespaces), they can escape container boundaries and compromise the host.
* **Mitigation in PoC**: Non-root user execution, `cap_drop: [ALL]`, `no-new-privileges:true`, and a restrictive Seccomp filter denying dangerous syscalls (`ptrace`, `clone3`, `bpf`, `mount`).

### 3.2 Compromised Docker Daemon or Host Root
* An attacker with root access on the physical host machine or access to `/var/run/docker.sock` can read container memory, inspect volumes, or bypass network namespaces. Docker socket mounts are strictly prohibited within Bayora Vault containers.

### 3.3 Hardware-Level Microarchitectural Side Channels
* The PoC mitigates software network timing side-channels via response bucketing. However, it does **not** protect against microarchitectural hardware attacks across shared CPU cores or hyperthreads (e.g., Spectre, Meltdown, L1TF, MDS, Rowhammer, or power analysis).

### 3.4 Key Compromise / Stolen Secrets
* If the Ed25519 private key (`.secrets/ed25519_private.pem`) or the HMAC master secret (`.secrets/hmac_secret`) is compromised on the host, an attacker can forge capability tokens or construct an alternate valid audit chain.

### 3.5 Semantic Evasion of Blue Filter Rules
* The Vault guarantees that Blue filters are executed securely and without information leaks. It does **not** guarantee that a given Blue regex or classifier will catch every possible semantic jailbreak or linguistic obfuscation technique.

---

## 4. When Guarantees Fail (Boundary Conditions & Failure Modes)

| Guarantee | Boundary Condition Where Guarantee Fails | Observable Impact & Detection |
|---|---|---|
| **Network Isolation** | Gateway container compromise via Remote Code Execution (RCE). | Since Gateway is attached to all internal networks, compromising Gateway allows cross-network packet forwarding. |
| **Commit-Reveal Sealing** | Session store memory corruption or premature conclusion trigger. | Blue could query results before attack concludes. Detected by breach test 03. |
| **Timing Padding** | Processing latency exceeds the configured bucket duration (e.g., complex model takes > 200ms). | Gateway must spill over into the next bucket boundary ($2 \times B$). Extreme tail latencies can reveal compute complexity. |
| **Audit Immutability** | Storage corruption or truncation of the append-only audit log file. | Detected immediately by `scripts/verify.py` as a broken hash linkage or missing signature. |
| **Availability (DoS)** | Unbounded concurrent session creation exhausting Gateway memory limits (`256m`). | Container crashes with OOMKilled; Docker restarts container cleanly. |

---

## 5. Future Work & Production Hardening

To transition this proof of concept to enterprise defense environments:

1. **MicroVM Isolation**: Replace container runtimes with lightweight virtual machines using Firecracker or Kata Containers (gVisor / Cloud Hypervisor) to provide dedicated kernel boundaries per team.
2. **Confidential Computing (TEE)**: Execute model inference inside hardware-encrypted enclaves (AMD SEV-SNP or Intel TDX) to protect model weights and KV-cache against host memory inspection.
3. **Hardware Security Module (HSM)**: Relocate Ed25519 signing keys into an HSM (or AWS KMS / Cloud KMS) with hardware-enforced append-only audit policies.
4. **Adaptive Jittered Padding**: Implement randomized differential timing padding to protect against statistical averaging attacks over millions of automated requests.
5. **Verifiable Transparency Log**: Integrate with public append-only verifiable log infrastructure (such as Sigstore / Rekor) for publicly verifiable third-party auditing.
