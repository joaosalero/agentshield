# Security policy

Use GitHub private vulnerability reporting. Do not submit credential values,
personal filesystem paths, or production telemetry in issues. Reports should
include the affected commit, platform, minimal synthetic reproduction and
security impact. An acknowledgment is targeted within seven days.

AgentShield intentionally records credential names but never values. A report
that contains a value is a security defect and should be reported privately.
The current supported target is the latest `main` branch on Linux/WSL.
