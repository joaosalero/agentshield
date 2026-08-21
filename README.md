# AgentShield

**Real-time credential, privilege, and resource visibility for AI agents.**

AgentShield answers a question that becomes more important as autonomous agents
gain access to developer machines: **what can this agent access right now, and
what deserves attention?**

It observes a running process without retaining or emitting credential values, evaluates its
effective privileges and open resources, and produces explainable security
findings in a live desktop dashboard or machine-readable event stream.

> Linux/WSL preview. AgentShield is an observability control, not a complete
> sandbox. It does not claim to block every operating-system action.

Build requirements are a C11 compiler, a C++17 compiler, OpenSSL 3 development
headers, and JDK 17 for the optional desktop dashboard.

## Capabilities

- Live inventory of credential-like environment variable **names**
- Credential values are discarded while parsing and are never retained or emitted
- Effective UID and Linux capability detection
- Sensitive open-file and network-socket visibility
- Explainable rules with severity, evidence, score, and remediation
- Access-drift detection for newly granted or revoked credentials, sensitive files,
  sockets, privileges, and monitoring coverage
- A bounded live access timeline that calls attention to dangerous new grants
- Versioned allow/deny/approval policies with fail-closed supervised enforcement
- Launch-scoped approvals that are never persisted
- Point-in-time inspection, continuous monitoring, or supervised command launch
- Authenticated HMAC-SHA-256 audit chain with offline verification
- Verified `io.helix-sentinel.agentshield/v1` JSONL export without network transmission
- Java Swing dashboard with live credential and finding tables
- Strict privacy mode for shared telemetry and demonstrations
- Owner-only audit keys/logs, append pre-verification, and fail-closed size retention
- Secure supervised execution with `no_new_privs`, no core dumps, descriptor
  isolation, process groups, and optional CPU/memory/process limits
- Read-only `/proc` sensor written in C and policy engine written in C++17
- Unit, integration, redaction, sanitizer, CMake, and CI validation

## Architecture

```text
/proc metadata → C sensor → C++ risk engine → JSONL/TSV → Java dashboard
                                             └────────→ Helix Sentinel (future)
```

The C sensor uses a fixed-size, stable ABI. The C++ layer owns policy and
serialization. The desktop app runs across a process boundary, so the same
event contract can be consumed by another UI or a security platform.

## Quick start

```bash
make
./build/agentshield inspect $$
./build/agentshield watch 12345 --interval 1000
./build/agentshield run -- python3 your_agent.py
./build/agentshield run --privacy strict --max-memory-mb 2048 \
  --max-cpu-seconds 600 -- python3 your_agent.py
./build/agentshield run --policy policies/baseline.policy \
  --approve credential:MY_SCOPED_TOKEN -- python3 your_agent.py
./build/agentshield audit init-key audit.key
./build/agentshield watch 12345 --privacy strict \
  --audit audit.jsonl --audit-key audit.key
./build/agentshield audit verify audit.jsonl --audit-key audit.key
./build/agentshield audit export audit.jsonl --audit-key audit.key > helix.jsonl
```

Desktop dashboard (JDK 17+):

```bash
make java
make run-gui
```

Alternative CMake build:

```bash
cmake -S . -B build-cmake
cmake --build build-cmake
ctest --test-dir build-cmake --output-on-failure
```

## Event model

Each JSON line follows the backward-compatible `io.agentshield.snapshot/v1` contract and contains:

- process identity and effective privilege metadata; command arguments are omitted;
- credential names and classifications, never values;
- security-relevant open resources;
- normalized findings and a bounded 0–100 risk score.
- a `changes` array describing grants and revocations since the preceding
  successful snapshot; the first snapshot establishes the in-memory baseline.
- an optional `policy` object containing normalized decisions, approval state,
  and whether supervised execution was blocked.

Change events contain direction, category, severity, a privacy-filtered
identifier, and an `attention` flag. A lost observability surface is treated as
a high-severity grant of uncertainty instead of being mistaken for reduced
exposure. Baselines exist only in monitor memory and are not persisted.

Reports may expose local paths and should be handled as security telemetry.

## Current threat model and limitations

The dashboard presents **observed exposure**, not a complete inventory of every
permission or credential available through external brokers. The preview monitors processes owned by the current user. Linux may restrict
inspection through `ptrace_scope`, containers, user namespaces, or `/proc`
mount options. Socket identifiers show that network access exists but do not yet
resolve every inode to a remote endpoint. Environment variables can change
between snapshots, and a compromised kernel is outside the trust boundary.

See [the policy guide](docs/POLICY.md), [authenticated audit guide](docs/AUDIT.md), [the security architecture](docs/SECURITY_ARCHITECTURE.md),
[privacy guide](docs/PRIVACY.md), [threat model](docs/THREAT_MODEL.md), and
[security policy](SECURITY.md).

## Roadmap

- eBPF event sensor for file, process, and network activity
- Windows ETW and macOS Endpoint Security adapters
- signed policy bundles and externally anchored audit receipts
- native Helix Sentinel transport adapter with mutual authentication

## License

MIT. See [LICENSE](LICENSE).
