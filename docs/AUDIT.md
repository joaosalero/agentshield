# Authenticated audit and Helix export

AgentShield audit logs are append-only JSON Lines envelopes authenticated with
HMAC-SHA-256. Each record contains a sequence number, the preceding record MAC,
an event digest, the encoded AgentShield event, and a MAC over all of that
metadata. Verification detects modified, inserted, removed, reordered, or
truncated records when the expected final MAC is retained separately.

## Create and protect a key

```bash
agentshield audit init-key ~/.local/share/agentshield/audit.key
```

The command uses operating-system cryptographic randomness and creates a new
`0600` file without following a symbolic link or replacing an existing file.
The key is not an encryption key: it authenticates the log but does not conceal
standard-mode identifiers. Store it separately from exported logs and include
it in protected backup and recovery procedures. Never commit it.
The repository ignore rules defensively exclude `*.key` and common audit/export
JSONL names, but operators must still store production telemetry outside the
source tree.

## Record and bound telemetry

```bash
agentshield watch 12345 --privacy strict \
  --audit ~/.local/share/agentshield/session.jsonl \
  --audit-key ~/.local/share/agentshield/audit.key \
  --audit-max-bytes 67108864
```

Both the log and key are mandatory. Before appending, AgentShield validates the
entire existing chain with the supplied key. It rejects non-regular files,
final-component symbolic links, unexpected ownership, group/other access, and
oversized logs. The configured size is a hard retention boundary: when the next
record would exceed it, monitoring fails closed instead of deleting or
overwriting evidence silently. One writer holds an exclusive lock for the
session, and a single session file is capped at 256 MiB.

Retention deletion is deliberately an operator-controlled action. Verify and
archive the log, retain its final MAC in a separate protected system, and then
replace the session file according to organizational policy. This preserves a
clear custody boundary and avoids an unattended monitor destroying evidence.

## Verify

```bash
agentshield audit verify session.jsonl --audit-key audit.key
```

Success emits a machine-readable verification receipt containing the record
count and final MAC. Any structural, digest, chain, sequence, or authentication
failure exits non-zero. Verification is meaningful only while the HMAC key and
trusted final MAC remain protected from an attacker who can rewrite the log.

## Export to Helix Sentinel

```bash
agentshield audit export session.jsonl --audit-key audit.key > helix.jsonl
```

Export occurs only after complete authentication. Each output line uses
`io.helix-sentinel.agentshield/v1`, includes integrity metadata, and embeds the
original `io.agentshield.snapshot/v1` event. It contains no audit key and does
not perform network transmission. Prefer strict privacy before collection when
the export will leave the local machine.

## Security limitations

- HMAC provides integrity and authenticity, not encryption.
- A copied log can be rolled back to an earlier valid prefix unless its trusted
  final MAC or verification receipt is anchored separately.
- A process that steals the key can forge records. Keep agent processes unable
  to read the key and audit directory.
- The current command verifies one session file at a time; external archival
  systems own cross-session retention and immutable-storage policy.
