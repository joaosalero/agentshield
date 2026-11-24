# Validation evidence

This file records security-relevant integration evidence that ordinary hosted
CI runners may be unable to exercise. It complements, and does not replace, the
GitHub Actions checks.

## Delegated cgroup v2 integration

- Date: 2026-08-22
- Platform: Ubuntu 26.04 LTS on WSL2, Linux
  `6.6.114.1-microsoft-standard-WSL2`, x86_64
- Controllers: `cpu`, `memory`, and `pids` available under unified cgroup v2
- Delegation provider: user systemd transient service with `Delegate=yes`
- Required command: `make cgroup-test-required`
- Result: pass, without a skip

The required test proves all of the following against the real kernel
interface:

1. missing delegation fails closed;
2. a supervised process enters the AgentShield leaf before running;
3. `memory.max`, `pids.max`, and `cpu.max` receive the requested values;
4. temporary leaves are removed after execution; and
5. `cgroup.kill` terminates a descendant that created a new session and ignored
   `SIGTERM`.

`tests/test_cgroup.sh` may skip its positive path during the ordinary `make
test` target when a user service manager is unavailable. Release qualification
must use `make cgroup-test-required`; that target converts the missing facility
into a failure. A binary release must preserve a non-skipped receipt from its
release environment.

## Cryptographic audit integration

- Provider during this validation: OpenSSL 3.5.5
- Commands: `make test` and `make sanitize`
- Result: pass

Coverage includes SHA-256 and RFC HMAC vectors, canonical Base64 enforcement,
event mutation, wrong-key rejection, sequence/chain validation, exclusive
writer behavior, retention limits, strict privacy, and verified Helix export.

## Behavioral anomaly calibration baseline

- Date: 2026-08-25
- Command: `make test`
- Synthetic scenarios: 20 independent in-memory sessions
- Complete normal observations evaluated after warm-up: 140
- False-positive rate: 0.00 in this bounded synthetic set
- Material exposure surges detected: 20/20 (1.00 detection rate)

`tests/test_behavior_eval.cpp` is a regression gate, not a claim about production
prevalence or general model accuracy. Real-world thresholds require a larger,
versioned corpus with representative agent workloads. The test additionally
verifies that incomplete observability cannot train the baseline and that an
advisory never changes deterministic risk or policy enforcement.

## Operational contracts and parser robustness

`tests/test_cli.sh` validates the versioned doctor response, required readiness
fields, and explicit privacy declaration. It also verifies that Prometheus
output contains aggregate coverage and exposure metrics while excluding
synthetic credential names, values, and process identifiers.

`make fuzz-smoke` applies 10,000 deterministic mutations to the policy and audit
record parsers under AddressSanitizer and UndefinedBehaviorSanitizer. This is a
bounded regression gate, not a substitute for a long-running coverage-guided
fuzzing campaign.
