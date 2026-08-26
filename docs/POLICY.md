# Policy language v1

AgentShield policies turn observed exposure into explicit allow, approval, or
deny decisions. Policies are local text files and never contain credential
values.

## Secure loading

The final path component must not be a symbolic link. The file must be regular,
owned by the current user or root, no larger than 64 KiB, and not writable by
group or other users. Unknown directives, duplicate singleton settings,
unsupported versions, invalid values, and oversized lines fail closed.

For automated rollout, pin the exact content delivered through the trusted
control plane:

```bash
digest=$(sha256sum /etc/agentshield/baseline.policy | awk '{print $1}')
agentshield run --policy /etc/agentshield/baseline.policy \
  --policy-sha256 "$digest" -- python3 agent.py
```

`--policy-sha256` accepts exactly 64 lowercase hexadecimal characters and uses
a constant-time comparison. A missing policy or digest mismatch fails before
the supervised command starts. The digest must arrive through an independently
authenticated channel; content addressing detects substitution but does not
identify the policy publisher. Signed policy bundles remain a roadmap item.

## Directives

```text
version 1
mode enforce
require-full-coverage true
allow-root false
allow-capabilities false
max-risk-score 74

default credential approval
default sensitive-file approval
default network approval

credential "SYNTHETIC_DEMO_API_TOKEN" allow
resource-prefix "/reviewed/workspace/" allow
network-prefix "tcp://127.0.0.1:" allow
network-endpoint "tcp://203.0.113.8:443" approval
```

- `mode audit` reports decisions without stopping a process.
- `mode enforce` is accepted only by `agentshield run`. Blocking decisions
  terminate the supervised process group and return exit code `3`.
- The initial executable is held at the Linux `exec` boundary and evaluated
  before its first userspace instruction. Failure to establish this gate aborts
  the launch.
- Credential rules are exact and case-sensitive.
- Resource rules use absolute path prefixes; the longest matching prefix wins.
- Network rules use attributed `tcp://`, `tcp6://`, `udp://`, or `udp6://`
  identifiers. `network-endpoint` is an exact match and should be preferred for
  a single host and port. `network-prefix` deliberately matches textual prefixes
  such as every loopback TCP port; the longest matching prefix wins. Unattributed sockets
  retain their inode identifier and therefore fall back to `default network`.
- Deny decisions cannot be overridden.
- Approval decisions require a launch-scoped `--approve category:value` or
  `--approve category:*`. Approvals are never persisted.
- Missing required coverage, forbidden root/capabilities, and a risk score over
  the configured maximum are always deny decisions.

## Operational guidance

Start in `audit` mode, inspect representative workloads, then change to
`enforce`. Prefer exact approvals over wildcards. Store policies in a trusted
owner-controlled directory and review every change through version control.
The desktop dashboard accepts an optional audit policy and displays its
decisions in the **Policy decisions** tab. Enforce policies are intentionally
restricted to supervised `run` mode.

Policy enforcement is a supervisory control, not kernel mandatory access
control. A hostile descendant may escape a process group; cgroup and LSM
containment remain separate layers. A later `exec`, credential injection, or
resource open can occur between samples; use direct agent execution and do not
treat this layer as a substitute for kernel enforcement.
