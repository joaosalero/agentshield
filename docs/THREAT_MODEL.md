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

## Non-goals for v0.1

AgentShield is not antivirus software, a kernel security module, a secrets
manager, or proof that an observed process is safe. Enforcement will only be
introduced with explicit fail-closed semantics and platform-specific tests.
