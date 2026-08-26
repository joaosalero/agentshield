# Threat model

## Protected assets

Agent credentials, local files, process privileges, security telemetry, policy
decisions, and the user's ability to understand an agent's effective access.

## Trust boundaries

The monitored agent is untrusted. `/proc` and the kernel are trusted for this
preview. The sensor, policy engine, dashboard, and future Helix Sentinel
connector are separate boundaries. JSON events are treated as sensitive because
they can contain process metadata and local paths.

## Principal threats

| Threat | Current control | Residual limitation |
|---|---|---|
| Credential exposure | Collect names only; redaction invariant test | A malicious process already knows its own environment |
| Excess privilege | Detect root UID and effective capabilities | Preview reports but does not revoke privileges |
| Sensitive file access | Inspect security-relevant open descriptors | Very short-lived opens may occur between snapshots |
| Data exfiltration | Attribute observed TCP/UDP sockets to local/remote endpoints and state | Payloads, Unix sockets and connections between samples are not observed |
| Telemetry injection or rewrite | Fixed event schema plus an authenticated HMAC-SHA-256 chain | HMAC does not encrypt data; the key must remain outside agent reach |
| Telemetry collection exhaustion | Fixed collection bounds and truncation finding | Very large process trees need aggregation controls |
| Protocol injection | Agent output discarded; TSV controls normalized; JSON escaped | Explicit output inheritance exposes terminal logs |
| Privilege escalation | `no_new_privs` default and capabilities finding | Existing privileges are observed, not revoked |
| Audit path attack | `O_NOFOLLOW`, ownership/type/mode validation, `0600`, bounded size | Trusted parent directories, root and a compromised kernel remain trusted |
| Audit deletion, reordering or truncation | Sequence, event digest, predecessor MAC, whole-file verification before append/export | A valid-prefix rollback is detectable only when the trusted final MAC is anchored separately |
| Audit forgery | Keyed HMAC with constant-time verification and a separately stored owner-only key | An attacker that steals the key can forge a replacement chain |
| Unbounded telemetry retention | Explicit byte ceiling fails closed before overflow | Archival and deletion remain deliberate operator actions |
| PID reuse | Process start time checked before and after snapshot | Snapshot fields are not an atomic kernel transaction |
| Access granted after initial inspection | Consecutive snapshots emit attention-marked drift events | A grant and revocation between samples may be missed |
| Drift event privacy leak | Category-aware strict redaction also covers changes | PID and severity remain available for correlation |
| Policy tampering or substitution | `O_NOFOLLOW`, type/owner/mode/size validation and strict versioned parsing | A trusted owner or root can intentionally replace policy content |
| Unreviewed sensitive access | Explicit decisions plus a pre-instruction gate for the initial executable | Later exec/access between samples requires LSM/event enforcement |
| Descendant escapes process group | Optional cgroup v2 membership before exec plus `cgroup.kill` | A hostile same-UID process may manipulate a user-delegated hierarchy; use UID/namespace separation for adversarial workloads |
| Resource exhaustion | RLIMIT plus optional cgroup memory, PID and CPU controls | Host-level contention outside the delegated subtree remains external |
| Approval replay | Approvals are launch-scoped and never persisted | Wildcard approvals intentionally broaden one supervised session |

## Non-goals for v0.1

AgentShield is not antivirus software, a kernel security module, a secrets
manager, immutable storage, or proof that an observed process is safe. Current
enforcement protects the initial supervised exec boundary; complete filesystem
and network enforcement still requires platform-specific kernel controls.
