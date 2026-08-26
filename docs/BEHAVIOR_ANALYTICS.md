# Local behavioral anomaly analytics

AgentShield maintains an in-memory baseline for each `watch` or supervised `run`
session. The baseline never leaves the monitor process and is discarded when the
session ends. It receives no credential values, command arguments, file contents,
user identity, or network payloads.

The initial detector observes five aggregate features:

- credential-name count;
- sensitive-file count;
- attributed network-connection count;
- active Linux-capability count;
- deterministic risk score.

It uses Welford's online algorithm to maintain a mean and sample variance without
retaining historical snapshots. Five complete observations are required before a
signal can be emitted. Incomplete-observability snapshots are ignored so lost
sensor coverage cannot train the baseline toward an unsafe zero.

A signal requires both a feature-specific minimum absolute change and at least
three standardized deviations from the session baseline. A zero-variance baseline
uses a conservative deterministic deviation only after the minimum change is met.
The anomaly score is bounded from 0 to 100 and includes the feature, observed
aggregate, baseline mean, standardized deviation, and sample count.

## Enforcement boundary

Behavioral output is explicitly `advisory`. Its finding has zero contribution to
the deterministic risk score, cannot create a policy decision, and cannot block or
approve execution. Existing rules remain the sole enforcement authority. Operators
must review the underlying deterministic evidence before acting on an anomaly.

This first version deliberately favors auditability over model complexity. It does
not claim population-level normality, cross-session learning, causal attribution,
or protection against slow baseline poisoning. Future calibration must use a
versioned synthetic evaluation set and report precision, recall, false-positive
rate, and time-to-detection before thresholds change.
