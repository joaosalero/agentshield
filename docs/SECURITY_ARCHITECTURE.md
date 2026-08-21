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
selects an audit file in the native monitor.

## Fail-closed behavior

Invalid policies, unsafe audit files, inability to apply a requested resource
limit, failure to isolate the process group and unsupported option combinations
terminate the operation with a non-zero code. Monitoring does not claim that a
failed snapshot is safe.

## Deliberate limits

Process-group termination uses a bounded `SIGTERM` grace period followed by
`SIGKILL`. A hostile descendant can create a new session and escape a process
group; complete tree containment requires the planned cgroup adapter.

This version observes and constrains a launched process but is not a kernel
mandatory-access-control system. Filesystem and network enforcement require the
planned eBPF/LSM or platform-native adapters. `RLIMIT_NPROC` semantics are
user-scoped on Linux and should be tested with the target workload.
