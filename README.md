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

## Capabilities

- Live inventory of credential-like environment variable **names**
- Credential values are discarded while parsing and are never retained or emitted
- Effective UID and Linux capability detection
- Sensitive open-file and network-socket visibility
- Explainable rules with severity, evidence, score, and remediation
- Point-in-time inspection, continuous monitoring, or supervised command launch
- JSON Lines contract designed for SIEM ingestion and future Helix Sentinel use
- Java Swing dashboard with live credential and finding tables
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

Each JSON line follows `io.agentshield.snapshot/v1` and contains:

- process identity and effective privilege metadata; command arguments are omitted;
- credential names and classifications, never values;
- security-relevant open resources;
- normalized findings and a bounded 0–100 risk score.

Reports may expose local paths and should be handled as security telemetry.

## Current threat model and limitations

The dashboard presents **observed exposure**, not a complete inventory of every
permission or credential available through external brokers. The preview monitors processes owned by the current user. Linux may restrict
inspection through `ptrace_scope`, containers, user namespaces, or `/proc`
mount options. Socket identifiers show that network access exists but do not yet
resolve every inode to a remote endpoint. Environment variables can change
between snapshots, and a compromised kernel is outside the trust boundary.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and [SECURITY.md](SECURITY.md).

## Roadmap

- eBPF event sensor for file, process, and network activity
- enforceable allow/deny/approval policy mode
- Windows ETW and macOS Endpoint Security adapters
- signed policy bundles and tamper-evident audit chains
- native Helix Sentinel ingestion adapter

## License

MIT. See [LICENSE](LICENSE).
