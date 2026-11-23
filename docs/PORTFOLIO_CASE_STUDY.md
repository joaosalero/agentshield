# AgentShield — engineering case study

## The problem

AI agents can inherit developer credentials, open files, network connections, and
Linux privileges that are invisible after launch. Traditional secret scanners find
values in code; sandbox products constrain execution. A separate observability
layer can explain which exposure signals are visible for a running process and
what changed since its prior snapshot, subject to the sensor's coverage limits.

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

## Validation scope and evidence

The repository distinguishes configured checks from recorded historical results.
The latter are documented in [VALIDATION.md](VALIDATION.md) and have not been
independently reproduced for every host or revision.

| Evidence | Result |
|---|---|
| Native, desktop, and CodeQL checks | Configured in [CI](../.github/workflows/ci.yml) for pushes and pull requests to `main`; required-check enforcement is a separate repository setting |
| Sanitizer suite | Historical receipt in [VALIDATION.md](VALIDATION.md) records passing AddressSanitizer and UndefinedBehaviorSanitizer runs |
| Behavioral regression set | 2026-08-25 receipt: 0/140 synthetic normal false positives; 20/20 surges detected |
| Packaging | `make deterministic-package` and `make verify-deb` check byte-for-byte repackaging and package contents; they do not prove reproducible compilation |
| Kernel containment | 2026-08-22 receipt: delegated cgroup v2 integration passed without a skip on the documented WSL2 host |
| Supply chain | Build targets generate a CycloneDX source-input inventory and unsigned in-toto build metadata with bound SHA-256 checks; these are not a complete runtime SBOM or a signed attestation |

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
