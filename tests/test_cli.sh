#!/usr/bin/env bash
set -euo pipefail
binary=${1:?binary required}
output=$(env SYNTHETIC_DEMO_API_KEY_NAME=not-a-real-secret "$binary" inspect $$)
python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["schema"]=="io.agentshield.snapshot/v1"; assert d["process"]["pid"]>0; assert "risk" in d; print("sensor integration: OK")' <<<"$output"
if grep -q 'not-a-real-secret' <<<"$output"; then echo "credential value leaked" >&2; exit 1; fi
echo "redaction invariant: OK"

set +e
run_output=$(env SYNTHETIC_DEMO_API_TOKEN=unique-canary-value "$binary" run --interval 10 -- sh -c 'exit 7' --api-key unique-argv-canary 2>/dev/null)
run_code=$?
set -e
test "$run_code" -eq 7
if grep -Eq 'unique-canary-value|unique-argv-canary' <<<"$run_output"; then echo "runtime secret leaked" >&2; exit 1; fi
echo "supervised exit status and argv redaction: OK"
