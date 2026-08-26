# AI and data-science strategy

AgentShield keeps enforcement deterministic. A model may explain verified telemetry,
prioritize remediation, and summarize a bounded incident window, but it never grants
access, changes policy, or lowers a risk score. The native engine remains the source of
truth and every AI statement is labelled as advisory.

## Recommended optional AI assistant

The first integration should use the OpenAI Responses API with structured output and
`gpt-5.6-terra` at low or medium reasoning. It provides a practical balance for concise
security explanations. `gpt-5.6-sol` is reserved for an explicitly requested deep
incident analysis, while `gpt-5.6-luna` is suitable for high-volume one-line event
classification after evaluation proves acceptable recall.

The feature is opt-in and disabled by default. Requests contain only normalized rule
IDs, severity, resource categories, redacted identifiers, and policy outcomes. They
must set `store: false`, use a privacy-preserving `safety_identifier`, enforce a JSON
schema, cap input/output size, apply timeouts, and never expose API keys to the monitored
agent or persist them in AgentShield configuration. Raw environment values, audit keys,
full local paths, user names, command arguments, and endpoint identifiers are excluded.

Suggested structured response fields are `summary`, `why_it_matters`,
`recommended_actions`, `confidence`, and `evidence_rule_ids`. The UI must distinguish
model inference from sensor evidence and offer a fully local deterministic explanation
when the API is unavailable.

## Data-science roadmap

Useful local techniques do not require sending telemetry to a service:

- exponentially weighted baselines for credential, file, connection, and privilege
  counts;
- robust z-scores using median absolute deviation for sudden exposure growth;
- categorical novelty detection for a previously unseen resource or destination class;
- change-point detection for sustained shifts in the agent's access profile;
- per-agent risk calibration evaluated with precision, recall, false-positive rate, and
  time-to-detection.

Learning is local, bounded, and opt-in. Models train only on redacted feature vectors,
have explicit retention limits, and can be reset. No anomaly model automatically blocks
a process; it creates an explainable finding that deterministic policy may separately
handle. Embeddings and vector databases are intentionally deferred until measured search
quality demonstrates a need.

## Evaluation gate

Before enabling AI by default, maintain a versioned synthetic evaluation set covering
safe, suspicious, policy-blocked, and incomplete-observability scenarios. Compare every
candidate model/prompt for schema validity, evidence faithfulness, unsafe recommendations,
latency, and cost. A model update must not ship when it invents access not present in the
supplied evidence or recommends weakening privacy controls.
