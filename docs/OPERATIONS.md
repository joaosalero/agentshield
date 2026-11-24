# Enterprise operations guide

This guide covers local health evaluation, privacy-safe metrics, alert semantics,
and incident evidence for AgentShield. The preview does not open a listening
socket or transmit telemetry. An operator must explicitly collect command output
with a trusted, access-controlled system.

## Readiness diagnostics

Run the diagnostic before monitoring a workload:

```bash
agentshield doctor
```

The versioned `io.agentshield.doctor/v1` JSON document reports whether the
required `/proc` surfaces are available and whether optional cgroup v2 tree
containment is delegated. It contains no PID, username, hostname, path, endpoint,
environment-variable name, or credential value.

- Exit `0` means core monitoring is ready. Optional containment can still be
  unavailable.
- Exit `2` means a required monitoring surface is unavailable. Treat the host as
  not ready; do not infer that the workload has no exposure.
- `runningAsRoot` is a safety signal, not an identity. AgentShield should normally
  run as the same unprivileged user as the supervised agent.

## Prometheus text exposition

Generate one aggregate snapshot suitable for a trusted node collector:

```bash
agentshield inspect PID --format prometheus > /restricted/path/agentshield.prom
```

Prometheus output is deliberately limited to `inspect`; AgentShield does not
serve HTTP and does not repeatedly concatenate exposition documents. The output
contains aggregate counts, risk, coverage, drift, policy state, and truncation.
It contains no target PID or user-controlled labels, preventing credential,
path, endpoint, and label-cardinality exposure.

Recommended alert conditions:

| Signal | Condition | Operator response |
|---|---|---|
| `agentshield_coverage` | any required surface is `0` | investigate host permissions and treat exposure as unknown |
| `agentshield_policy_blocked` | equals `1` | review the deterministic decision; never auto-approve |
| `agentshield_access_changes{direction="attention"}` | greater than `0` | inspect the authenticated event timeline |
| `agentshield_collection_truncated` | greater than `0` | reduce workload exposure or review bounded sensor limits |
| `agentshield_risk_score` | sustained increase or local policy threshold | investigate findings and access drift |

Thresholds must be calibrated to the environment. Metrics are current-state
evidence, not a substitute for authenticated audit retention.

## Evidence and incident workflow

1. Preserve the audit file and its key separately with owner-only permissions.
2. Stop or isolate the workload through an approved operational control.
3. Run `agentshield audit verify` before analysis or export.
4. Record the final MAC in an independently protected incident system.
5. Export only with strict privacy when evidence will leave the host.
6. Rotate to a new audit file according to the organization's retention policy;
   never edit or truncate an active chain in place.

AgentShield does not implement centralized retention, paging, IAM, or immutable
storage. Those systems must enforce authentication, tenant boundaries, retention,
and access review around the generated evidence.

## Operational failure modes

- Missing `/proc` coverage is a high-severity uncertainty condition.
- Failure to verify an existing audit chain prevents append and export.
- Exhausting the configured audit size stops authenticated recording rather than
  silently rotating or deleting evidence.
- A requested cgroup limit fails closed when delegation is unavailable.
- Behavioral anomalies remain advisory and cannot change deterministic policy.

Use the [validation guide](VALIDATION.md) for test evidence and the
[security architecture](SECURITY_ARCHITECTURE.md) for trust boundaries.
