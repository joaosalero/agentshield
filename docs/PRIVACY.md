# Privacy and data handling

AgentShield applies data minimization at collection and serialization boundaries.

## Collected metadata

- process identifiers, executable path, working directory, UID and capabilities;
- names of environment variables classified as credential-like;
- identifiers of security-relevant open descriptors;
- derived findings, severity and risk score.

Environment values and command arguments are discarded during parsing and are
not retained in snapshots, events, audit files or the desktop interface.

## Privacy modes

- `standard` supports local investigation and includes credential names and
  observed resource paths. Treat its output as sensitive security telemetry.
- `strict` replaces process names, credential names, executable paths, working
  directories and resource identifiers with explicit redaction markers. Use it for shared logs,
  demonstrations and external SIEM transport.

Strict events retain PID/PPID, UID, capability flags, timestamps, severity and
risk scores because they are required for correlation. Deployments where these
identifiers are personal data must apply access control and retention policy.

No telemetry is transmitted by AgentShield. Output exists only on stdout, in
the local dashboard, in an explicitly requested audit file, or in an explicitly
requested local Helix export stream.

Access-change events use the same redaction boundary as snapshots. Strict mode
never reveals the credential name or resource identifier that changed. The
comparison baseline remains in process memory for the life of the monitor and
is discarded when monitoring stops.

## Audit integrity and retention

Audit logs and HMAC keys are created or accepted only as `0600` regular files
owned by the effective user. A symbolic link in the final path component is
rejected; operators must also choose a trusted parent directory. Existing logs
are completely authenticated before append. A configurable byte ceiling stops
collection rather than silently deleting evidence. Operators remain responsible for:

- selecting `strict` mode when identifiers are unnecessary;
- defining an appropriate retention period;
- encrypting storage and backups;
- restricting SIEM ingestion and deletion permissions;
- securely removing expired telemetry according to organizational policy.

HMAC authenticates but does not encrypt telemetry. Strict privacy remains the
appropriate collection mode for logs that may be shared. Helix export verifies
the complete source chain first and never includes the HMAC key.

AgentShield does not silently weaken these checks. An unsafe audit destination
causes the operation to fail.
