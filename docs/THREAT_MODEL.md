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
| Data exfiltration | Signal open sockets | Endpoint attribution requires the planned event sensor |
| Telemetry injection | JSON escaping and fixed event schema | Event signing is planned |
| Resource exhaustion | Fixed collection bounds and truncation finding | Very large process trees need aggregation controls |
| Protocol injection | Agent output discarded; TSV controls normalized; JSON escaped | Explicit output inheritance exposes terminal logs |
| Privilege escalation | `no_new_privs` default and capabilities finding | Existing privileges are observed, not revoked |
| Audit path attack | `O_NOFOLLOW`, ownership/type/mode validation, `0600` | Root and a compromised kernel remain trusted |
| PID reuse | Process start time checked before and after snapshot | Snapshot fields are not an atomic kernel transaction |
| Access granted after initial inspection | Consecutive snapshots emit attention-marked drift events | A grant and revocation between samples may be missed |
| Drift event privacy leak | Category-aware strict redaction also covers changes | PID and severity remain available for correlation |
| Policy tampering or substitution | `O_NOFOLLOW`, type/owner/mode/size validation and strict versioned parsing | A trusted owner or root can intentionally replace policy content |
| Unreviewed sensitive access | Explicit decisions plus a pre-instruction gate for the initial executable | Later exec/access between samples and process-group escape require cgroup/LSM containment |
| Approval replay | Approvals are launch-scoped and never persisted | Wildcard approvals intentionally broaden one supervised session |

## Non-goals for v0.1

AgentShield is not antivirus software, a kernel security module, a secrets
manager, or proof that an observed process is safe. Enforcement will only be
introduced with explicit fail-closed semantics and platform-specific tests.
