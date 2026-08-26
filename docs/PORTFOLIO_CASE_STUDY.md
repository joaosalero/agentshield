# AgentShield — engineering case study

## The problem

AI agents can inherit developer credentials, open files, network connections, and
Linux privileges that are invisible after launch. Traditional secret scanners find
values in code; sandbox products constrain execution; neither directly answers what
a specific running agent can access at this moment and what changed since its prior
snapshot.

## Product decision

AgentShield treats runtime access as explainable security evidence. It observes a
user-owned Linux process, normalizes access metadata, evaluates deterministic rules,
and presents the result through a desktop console or machine-readable stream. It is
deliberately an observability and policy control rather than a claim of perfect OS
mediation.

## Why three languages

| Layer | Language | Engineering rationale |
|---|---|---|
| Sensor | C11 | Small fixed-size ABI and direct, read-only `/proc` integration |
| Risk, policy, audit | C++17 | Typed domain model, deterministic evaluation, bounded serialization |
| Desktop console | Java 17 | Portable native desktop UI isolated across a process boundary |

The split is not cosmetic. The sensor cannot make policy decisions, the dashboard
cannot access credential values, and enforcement remains testable without the UI.

## Security decisions

- Credential values are discarded during parsing and are never retained or emitted.
- Missing observability creates a high-severity uncertainty finding instead of a
  misleading empty result.
- Supervised execution disables core dumps, closes inherited descriptors, applies
  `no_new_privs`, isolates process groups, and supports delegated cgroup limits.
- Policy is versioned and fail-closed; approvals exist only for one launch.
- Audit records form an HMAC-SHA-256 chain that is verified before append and before
  Helix export.
- Behavioral anomaly detection is in-memory and advisory. It contributes zero points
  to deterministic risk and cannot approve or block execution.

## Measured evidence

| Evidence | Result |
|---|---|
| Native, desktop, and CodeQL checks | Required on protected `main` |
| Sanitizer suite | AddressSanitizer and UndefinedBehaviorSanitizer pass |
| Behavioral regression set | 0/140 synthetic normal false positives; 20/20 surges detected |
| Packaging | Byte-for-byte deterministic Linux archive and Debian installer verification |
| Kernel containment | Delegated cgroup v2 integration validated without skip |
| Supply chain | CycloneDX input inventory, in-toto build metadata, bound SHA-256 checks |

These results are bounded engineering evidence, not claims of production prevalence,
formal verification, or compliance certification.

## Product experience

The desktop console surfaces credential-name exposure, open resources, findings,
policy decisions, and an access timeline. A guided Demo Lab progressively demonstrates
a safe baseline, credential exposure, network approval, deterministic denial, and
containment using synthetic data and reserved destinations only.

## Trade-offs and limitations

The preview supports Linux/WSL and user-owned processes. `/proc` polling can miss
short-lived activity; kernel restrictions can reduce coverage; the behavioral set is
synthetic; and a compromised kernel is outside the trust boundary. These constraints
are explicit so the project remains technically credible.

## Next enterprise phase

Enterprise development would add an eBPF sensor, Windows ETW and macOS Endpoint
Security adapters, signed policy distribution, centralized RBAC/SSO, tenant isolation,
SIEM transport, operational SLOs, independent penetration testing, and compliance
evidence. See [ROADMAP.md](ROADMAP.md).
