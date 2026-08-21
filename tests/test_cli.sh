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

strict_output=$(env SYNTHETIC_DEMO_PRIVATE_TOKEN=another-canary "$binary" run --interval 10 --privacy strict -- sleep 0.1)
python3 -c 'import json,sys; rows=[json.loads(x) for x in sys.stdin if x.strip()]; assert rows; assert any(c["name"]=="[credential name redacted]" for r in rows for c in r["credentials"]); assert all(r["process"]["executable"]=="[executable path redacted]" and r["process"]["name"]=="[process name redacted]" for r in rows); print("strict privacy: OK")' <<<"$strict_output"
if grep -Eq 'SYNTHETIC_DEMO_PRIVATE_TOKEN|another-canary' <<<"$strict_output"; then echo "strict privacy leaked an identifier" >&2; exit 1; fi

"$binary" run --interval 10 -- sh -c 'grep -Eq "^NoNewPrivs:[[:space:]]+1" /proc/self/status' >/dev/null
exec 9</dev/null
"$binary" run --interval 10 -- sh -c 'test ! -e /proc/self/fd/9' >/dev/null
exec 9<&-
"$binary" run --interval 10 -- sh -c 'test "$(ulimit -c)" = 0' >/dev/null
printf 'sensitive-terminal-input' | "$binary" run --interval 10 -- sh -c 'test -z "$(cat)"' >/dev/null
"$binary" run --interval 10 --max-memory-mb 64 --max-cpu-seconds 2 -- sh -c 'grep -Eq "^Max cpu time[[:space:]]+2[[:space:]]+2" /proc/self/limits; grep -Eq "^Max address space[[:space:]]+67108864[[:space:]]+67108864" /proc/self/limits' >/dev/null
"$binary" run --interval 10 --max-processes 32 -- sh -c 'while IFS= read -r line; do case "$line" in "Max processes"*) set -- $line; test "$3" = 32 && test "$4" = 32; exit;; esac; done < /proc/self/limits; exit 1' >/dev/null
"$binary" run --interval 10 --allow-new-privs -- sh -c 'grep -Eq "^NoNewPrivs:[[:space:]]+0" /proc/self/status' >/dev/null
inherit_stdout=$(mktemp)
inherit_stderr=$(mktemp)
"$binary" run --interval 10 --agent-output inherit -- sh -c 'echo agent-diagnostic-marker; sleep 0.05' >"$inherit_stdout" 2>"$inherit_stderr"
grep -q agent-diagnostic-marker "$inherit_stderr"
if grep -q agent-diagnostic-marker "$inherit_stdout"; then echo "agent output contaminated telemetry" >&2; exit 1; fi
python3 -c 'import json,sys; [json.loads(x) for x in open(sys.argv[1]) if x.strip()]' "$inherit_stdout"
rm -f "$inherit_stdout" "$inherit_stderr"
echo "supervised isolation controls: OK"

drift_output=$(
  drift_dir=$(mktemp -d)
  trap 'rm -rf "$drift_dir"' EXIT
  drift_file="$drift_dir/synthetic.env"
  baseline_ready="$drift_dir/baseline-ready"
  close_access="$drift_dir/close-access"
  exit_agent="$drift_dir/exit-agent"
  telemetry="$drift_dir/telemetry.jsonl"
  : >"$drift_file"
  "$binary" run --interval 20 --audit "$telemetry" -- sh -c 'while test ! -e "$2"; do sleep 0.01; done; exec 8<"$1"; while test ! -e "$3"; do sleep 0.01; done; exec 8<&-; while test ! -e "$4"; do sleep 0.01; done' sh "$drift_file" "$baseline_ready" "$close_access" "$exit_agent" >"$drift_dir/stdout.jsonl" &
  drift_monitor=$!
  for _ in $(seq 1 200); do test -s "$telemetry" && break; sleep 0.01; done
  test -s "$telemetry"
  : >"$baseline_ready"
  for _ in $(seq 1 200); do grep -q '"direction":"GRANTED".*"category":"filesystem"' "$telemetry" && break; sleep 0.01; done
  grep -q '"direction":"GRANTED".*"category":"filesystem"' "$telemetry"
  : >"$close_access"
  for _ in $(seq 1 200); do grep -q '"direction":"REVOKED".*"category":"filesystem"' "$telemetry" && break; sleep 0.01; done
  grep -q '"direction":"REVOKED".*"category":"filesystem"' "$telemetry"
  : >"$exit_agent"
  wait "$drift_monitor"
  cat "$telemetry"
)
python3 -c 'import json,sys; rows=[json.loads(x) for x in sys.stdin if x.strip()]; changes=[c for r in rows for c in r["changes"]]; assert any(c["direction"]=="GRANTED" and c["category"]=="filesystem" and c["attention"] for c in changes); assert any(c["direction"]=="REVOKED" and c["category"]=="filesystem" and not c["attention"] for c in changes); print("access drift timeline: OK")' <<<"$drift_output"

set +e
exec_error=$("$binary" run -- definitely-not-an-agentshield-command 2>&1 >/dev/null)
exec_code=$?
set -e
test "$exec_code" -eq 2
grep -q 'cannot execute supervised command' <<<"$exec_error"
echo "exec failure diagnostics: OK"

child_pid_file=$(mktemp)
"$binary" run --interval 10 -- sh -c 'trap "" TERM; echo $$ > "$1"; while :; do sleep 1; done' sh "$child_pid_file" >/dev/null &
monitor_pid=$!
for _ in $(seq 1 50); do test -s "$child_pid_file" && break; sleep 0.02; done
test -s "$child_pid_file"
stubborn_pid=$(cat "$child_pid_file")
kill -TERM "$monitor_pid"
for _ in $(seq 1 150); do kill -0 "$monitor_pid" 2>/dev/null || break; sleep 0.02; done
if kill -0 "$monitor_pid" 2>/dev/null; then kill -KILL "$monitor_pid"; echo "monitor failed to terminate stubborn group" >&2; exit 1; fi
wait "$monitor_pid" || true
if kill -0 "$stubborn_pid" 2>/dev/null; then echo "stubborn supervised process survived" >&2; exit 1; fi
rm -f "$child_pid_file"
echo "bounded TERM-to-KILL escalation: OK"

audit_dir=$(mktemp -d)
trap 'rm -rf "$audit_dir"' EXIT
audit_file="$audit_dir/audit.jsonl"
if "$binary" invalid-action --audit "$audit_dir/should-not-exist" >/dev/null 2>&1; then echo "invalid action accepted" >&2; exit 1; fi
test ! -e "$audit_dir/should-not-exist"
"$binary" inspect $$ --privacy strict --audit "$audit_file" >/dev/null
test "$(stat -c %a "$audit_file")" = 600
python3 -c 'import json,sys; rows=[json.loads(x) for x in open(sys.argv[1])]; assert rows' "$audit_file"
chmod 644 "$audit_file"
if "$binary" inspect $$ --audit "$audit_file" >/dev/null 2>&1; then echo "insecure audit mode accepted" >&2; exit 1; fi
ln -s "$audit_file" "$audit_dir/link"
if "$binary" inspect $$ --audit "$audit_dir/link" >/dev/null 2>&1; then echo "audit symlink accepted" >&2; exit 1; fi
mkfifo "$audit_dir/fifo"
set +e
timeout 2 "$binary" inspect $$ --audit "$audit_dir/fifo" >/dev/null 2>&1
fifo_code=$?
set -e
if test "$fifo_code" -eq 0 || test "$fifo_code" -eq 124; then echo "audit FIFO was accepted or blocked" >&2; exit 1; fi
echo "secure audit file controls: OK"
