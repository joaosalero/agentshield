# Security architecture

## Security defaults for supervised execution

`agentshield run` creates a dedicated process group and applies:

- `PR_SET_PDEATHSIG` so the supervised process receives `SIGTERM` if the
  monitor unexpectedly exits;
- `PR_SET_NO_NEW_PRIVS` by default;
- `RLIMIT_CORE=0` to prevent core dumps containing process memory;
- closure of inherited file descriptors above standard input/output/error;
- `/dev/null` for agent stdin/stdout/stderr by default, preventing terminal
  input capture, protocol injection and accidental log disclosure;
- optional hard limits for address space, CPU time and process count.

Disabling `no_new_privs` or inheriting agent input/output requires an explicit
CLI option. These options are intended for controlled diagnostics and increase risk.

The monitor itself is also non-dumpable and runs with a zero core-dump limit,
reducing exposure of transient bytes read from kernel metadata.

## Trust boundaries

The agent is untrusted. The Linux kernel and `/proc` are trusted measurement
sources. Sensor snapshots are validated against process start time before and
after collection to reject PID reuse. The C sensor, C++ policy engine, CLI/JSON
boundary and Java dashboard are independently testable layers.

For continuous monitoring, the engine compares consecutive successful
assessments. It emits explicit grant and revocation events for credential-like
names, sensitive resources, effective privilege state, and collection
coverage. A failed collection does not replace the last trusted baseline.

The desktop access timeline is bounded to 500 rows to avoid unbounded memory
growth. It is session-local and is not written unless the operator explicitly
selects an audit file and matching integrity key in the native monitor.

## Audit trust boundary

Audit events use a versioned envelope and an HMAC-SHA-256 chain backed by the
reviewed OpenSSL 3 cryptographic provider. The event
digest binds the exact serialized snapshot, the previous MAC binds ordering,
and the record MAC authenticates sequence, timestamp, predecessor, digest, and
event. Existing content must verify before append. Comparisons of authentication
values use OpenSSL's constant-time comparison. Non-canonical Base64 is rejected
so alternate textual encodings cannot bypass envelope integrity. Keys and logs require owner-only permissions, regular
file type, expected ownership, bounded size, and final-component symlink
rejection.

The audit key stays outside telemetry. Helix export is an offline transformation
performed only after whole-file verification; AgentShield does not connect to a
Helix endpoint. HMAC does not provide confidentiality or prevent rollback to a
valid prefix, so deployments must separately protect the key and anchor trusted
final MAC receipts.

## Fail-closed behavior

Invalid policies, missing or unsafe audit keys, invalid audit chains, retention
limit exhaustion, unsafe audit files, inability to apply a requested resource
limit, failure to isolate the process group and unsupported option combinations
terminate the operation with a non-zero code. Monitoring does not claim that a
failed snapshot is safe.

Policy files cross an administrative trust boundary and therefore use secure
open/type/owner/mode/size validation before parsing. The versioned parser
rejects unknown or duplicate configuration. In enforce mode, deny decisions
and unapproved approval decisions are emitted to telemetry before the monitor
terminates the supervised process group. Launch-scoped approvals exist only in
monitor memory and cannot override deny decisions.

Enforced launches use a parent-child `ptrace` exec gate. The initial executable
is stopped after the kernel completes `exec` but before it runs userspace code;
AgentShield evaluates the resulting process image and environment, then either
detaches and resumes it or kills it. If the gate cannot be established, launch
fails closed. Continuous sampling remains responsible for later drift and does
not provide the same pre-instruction guarantee for subsequent exec transitions.

## Deliberate limits

Process-group termination uses a bounded `SIGTERM` grace period followed by
`SIGKILL`. A hostile descendant can create a new session and escape a process
group; complete tree containment requires the planned cgroup adapter.

This version observes and constrains a launched process but is not a kernel
mandatory-access-control system. Filesystem and network enforcement require the
planned eBPF/LSM or platform-native adapters. `RLIMIT_NPROC` semantics are
user-scoped on Linux and should be tested with the target workload.
