#!/usr/bin/env bash
set -euo pipefail
binary=${1:?binary required}
version=$(python3 scripts/read_version.py VERSION)
test "$("$binary" --version)" = "AgentShield $version"
echo "version contract: OK"
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
python3 -c 'import json,sys; rows=[json.loads(x) for x in sys.stdin if x.strip()]; assert rows; assert any(c["name"]=="[credential name redacted]" for r in rows for c in r["credentials"]); assert all(r["process"]["executable"]=="[executable path redacted]" and r["process"]["name"]=="[process name redacted]" and r["process"]["cgroup"]=="[cgroup path redacted]" for r in rows); print("strict privacy: OK")' <<<"$strict_output"
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

python3 -c 'import socket,time; s=socket.socket(); s.bind(("127.0.0.1",0)); s.listen(); time.sleep(3)' &
network_pid=$!
for _ in $(seq 1 100); do test -d "/proc/$network_pid/fd" && ls -l "/proc/$network_pid/fd" 2>/dev/null | grep -q 'socket:' && break; sleep 0.01; done
network_output=$("$binary" inspect "$network_pid")
kill "$network_pid" 2>/dev/null || true
wait "$network_pid" 2>/dev/null || true
python3 -c 'import json,sys; d=json.load(sys.stdin); sockets=[r for r in d["resources"] if r["kind"]=="network_socket"]; assert sockets; assert any(r["network"]["attributed"] and r["network"]["protocol"]=="tcp" and r["network"]["localEndpoint"].startswith("127.0.0.1:") and r["network"]["state"]=="LISTEN" and r["identifier"].startswith("tcp://127.0.0.1:") for r in sockets); print("network endpoint attribution: OK")' <<<"$network_output"
strict_network=$(python3 -c 'import socket,time; s=socket.socket(); s.bind(("127.0.0.1",0)); s.listen(); time.sleep(3)' & target=$!; sleep 0.05; "$binary" inspect "$target" --privacy strict; kill "$target" 2>/dev/null || true; wait "$target" 2>/dev/null || true)
if grep -q '127.0.0.1' <<<"$strict_network"; then echo "strict network endpoint leaked" >&2; exit 1; fi
echo "strict network attribution privacy: OK"

drift_output=$(
  drift_dir=$(mktemp -d)
  trap 'rm -rf "$drift_dir"' EXIT
  drift_file="$drift_dir/synthetic.env"
  baseline_ready="$drift_dir/baseline-ready"
  close_access="$drift_dir/close-access"
  exit_agent="$drift_dir/exit-agent"
  telemetry="$drift_dir/telemetry.jsonl"
  audit_key="$drift_dir/audit.key"
  "$binary" audit init-key "$audit_key" >/dev/null
  : >"$drift_file"
  "$binary" run --interval 20 --audit "$telemetry" --audit-key "$audit_key" -- sh -c 'while test ! -e "$2"; do sleep 0.01; done; exec 8<"$1"; while test ! -e "$3"; do sleep 0.01; done; exec 8<&-; while test ! -e "$4"; do sleep 0.01; done' sh "$drift_file" "$baseline_ready" "$close_access" "$exit_agent" >"$drift_dir/stdout.jsonl" &
  drift_monitor=$!
  for _ in $(seq 1 200); do test -s "$telemetry" && break; sleep 0.01; done
  test -s "$telemetry"
  : >"$baseline_ready"
  for _ in $(seq 1 200); do "$binary" audit export "$telemetry" --audit-key "$audit_key" 2>/dev/null | grep -q '"direction":"GRANTED".*"category":"filesystem"' && break; sleep 0.01; done
  "$binary" audit export "$telemetry" --audit-key "$audit_key" | grep -q '"direction":"GRANTED".*"category":"filesystem"'
  : >"$close_access"
  for _ in $(seq 1 200); do "$binary" audit export "$telemetry" --audit-key "$audit_key" 2>/dev/null | grep -q '"direction":"REVOKED".*"category":"filesystem"' && break; sleep 0.01; done
  "$binary" audit export "$telemetry" --audit-key "$audit_key" | grep -q '"direction":"REVOKED".*"category":"filesystem"'
  : >"$exit_agent"
  wait "$drift_monitor"
  "$binary" audit export "$telemetry" --audit-key "$audit_key"
)
python3 -c 'import json,sys; rows=[json.loads(x)["event"] for x in sys.stdin if x.strip()]; changes=[c for r in rows for c in r["changes"]]; assert any(c["direction"]=="GRANTED" and c["category"]=="filesystem" and c["attention"] for c in changes); assert any(c["direction"]=="REVOKED" and c["category"]=="filesystem" and not c["attention"] for c in changes); print("access drift timeline: OK")' <<<"$drift_output"

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
audit_key="$audit_dir/audit.key"
"$binary" audit init-key "$audit_key" >/dev/null
test "$(stat -c %a "$audit_key")" = 600
if "$binary" audit init-key "$audit_key" >/dev/null 2>&1; then echo "existing audit key was overwritten" >&2; exit 1; fi
cp "$audit_key" "$audit_dir/insecure.key"
chmod 644 "$audit_dir/insecure.key"
if "$binary" inspect $$ --audit "$audit_dir/insecure-key.jsonl" --audit-key "$audit_dir/insecure.key" >/dev/null 2>&1; then echo "insecure audit key accepted" >&2; exit 1; fi
ln -s "$audit_key" "$audit_dir/key-link"
if "$binary" inspect $$ --audit "$audit_dir/key-link.jsonl" --audit-key "$audit_dir/key-link" >/dev/null 2>&1; then echo "audit key symlink accepted" >&2; exit 1; fi
touch "$audit_dir/empty.jsonl"
chmod 600 "$audit_dir/empty.jsonl"
if "$binary" audit verify "$audit_dir/empty.jsonl" --audit-key "$audit_key" >/dev/null 2>&1; then echo "empty audit log reported as verified evidence" >&2; exit 1; fi
if "$binary" invalid-action --audit "$audit_dir/should-not-exist" >/dev/null 2>&1; then echo "invalid action accepted" >&2; exit 1; fi
test ! -e "$audit_dir/should-not-exist"
if "$binary" inspect $$ --privacy strict --audit "$audit_file" >/dev/null 2>&1; then echo "audit without key accepted" >&2; exit 1; fi
"$binary" inspect $$ --privacy strict --audit "$audit_file" --audit-key "$audit_key" >/dev/null
"$binary" inspect $$ --privacy strict --audit "$audit_file" --audit-key "$audit_key" >/dev/null
test "$(stat -c %a "$audit_file")" = 600
verification=$("$binary" audit verify "$audit_file" --audit-key "$audit_key")
python3 -c 'import json,sys; row=json.load(sys.stdin); assert row["verified"] and row["records"]==2 and len(row["finalMac"])==64' <<<"$verification"
exported=$("$binary" audit export "$audit_file" --audit-key "$audit_key")
python3 -c 'import json,sys; rows=[json.loads(x) for x in sys.stdin if x.strip()]; assert len(rows)==2; assert all(r["schema"]=="io.helix-sentinel.agentshield/v1" and r["integrity"]["verified"] for r in rows); assert all(r["event"]["process"]["name"]=="[process name redacted]" for r in rows)' <<<"$exported"
cp "$audit_file" "$audit_dir/tampered.jsonl"
chmod 600 "$audit_dir/tampered.jsonl"
python3 -c 'import sys; p=sys.argv[1]; b=bytearray(open(p,"rb").read()); i=b.index(b"eventBase64")+14; b[i]=66 if b[i]!=66 else 65; open(p,"wb").write(b)' "$audit_dir/tampered.jsonl"
if "$binary" audit verify "$audit_dir/tampered.jsonl" --audit-key "$audit_key" >/dev/null 2>&1; then echo "tampered audit accepted" >&2; exit 1; fi
"$binary" audit init-key "$audit_dir/wrong.key" >/dev/null
if "$binary" audit verify "$audit_file" --audit-key "$audit_dir/wrong.key" >/dev/null 2>&1; then echo "wrong audit key accepted" >&2; exit 1; fi
if "$binary" inspect $$ --audit "$audit_dir/limited.jsonl" --audit-key "$audit_key" --audit-max-bytes 16 >/dev/null 2>&1; then echo "audit retention limit ignored" >&2; exit 1; fi
if "$binary" inspect $$ --audit-max-bytes 67108864 >/dev/null 2>&1; then echo "orphan audit retention option accepted" >&2; exit 1; fi
lock_log="$audit_dir/locked.jsonl"
"$binary" watch $$ --interval 20 --audit "$lock_log" --audit-key "$audit_key" >/dev/null &
lock_monitor=$!
for _ in $(seq 1 100); do test -s "$lock_log" && break; sleep 0.01; done
test -s "$lock_log"
if "$binary" inspect $$ --audit "$lock_log" --audit-key "$audit_key" >/dev/null 2>&1; then kill "$lock_monitor" 2>/dev/null || true; echo "concurrent audit writer accepted" >&2; exit 1; fi
kill "$lock_monitor" 2>/dev/null || true
wait "$lock_monitor" 2>/dev/null || true
chmod 644 "$audit_file"
if "$binary" inspect $$ --audit "$audit_file" --audit-key "$audit_key" >/dev/null 2>&1; then echo "insecure audit mode accepted" >&2; exit 1; fi
ln -s "$audit_file" "$audit_dir/link"
if "$binary" inspect $$ --audit "$audit_dir/link" --audit-key "$audit_key" >/dev/null 2>&1; then echo "audit symlink accepted" >&2; exit 1; fi
mkfifo "$audit_dir/fifo"
set +e
timeout 2 "$binary" inspect $$ --audit "$audit_dir/fifo" --audit-key "$audit_key" >/dev/null 2>&1
fifo_code=$?
set -e
if test "$fifo_code" -eq 0 || test "$fifo_code" -eq 124; then echo "audit FIFO was accepted or blocked" >&2; exit 1; fi
echo "authenticated audit, retention, and Helix export controls: OK"

policy_dir=$(mktemp -d)
policy_file="$policy_dir/enforce.policy"
cat >"$policy_file" <<'POLICY'
version 1
mode enforce
require-full-coverage false
allow-root true
allow-capabilities true
max-risk-score 100
default credential allow
default sensitive-file allow
default network allow
credential SYNTHETIC_POLICY_TOKEN approval
POLICY
chmod 600 "$policy_file"
set +e
blocked_marker="$policy_dir/must-not-run"
policy_output=$(env SYNTHETIC_POLICY_TOKEN=canary "$binary" run --interval 10 --policy "$policy_file" -- sh -c 'touch "$1"' sh "$blocked_marker")
policy_code=$?
set -e
test "$policy_code" -eq 3
test ! -e "$blocked_marker"
python3 -c 'import json,sys; rows=[json.loads(x) for x in sys.stdin if x.strip()]; assert rows; blocked=[r for r in rows if r["policy"]["blocked"]]; assert blocked and any(d["action"]=="APPROVAL" and d["blocking"] for r in blocked for d in r["policy"]["decisions"]); print("policy enforcement: OK")' <<<"$policy_output"
if grep -q canary <<<"$policy_output"; then echo "policy telemetry leaked a value" >&2; exit 1; fi

env SYNTHETIC_POLICY_TOKEN=canary "$binary" run --interval 10 --policy "$policy_file" --approve credential:SYNTHETIC_POLICY_TOKEN -- sh -c 'sleep 0.08' >/dev/null
audit_policy="$policy_dir/audit.policy"
sed 's/mode enforce/mode audit/' "$policy_file" >"$audit_policy"
chmod 600 "$audit_policy"
audit_ready="$policy_dir/audit-ready"
env SYNTHETIC_POLICY_TOKEN=canary sh -c 'touch "$1"; sleep 2' sh "$audit_ready" &
audit_target=$!
for _ in $(seq 1 100); do test -e "$audit_ready" && break; sleep 0.01; done
test -e "$audit_ready"
policy_tsv="$($binary inspect "$audit_target" --policy "$audit_policy" --privacy strict --format tsv)"
kill "$audit_target" 2>/dev/null || true
wait "$audit_target" 2>/dev/null || true
grep -q $'POLICY\tAPPROVAL\tcredential\t\[credential name redacted\].*ATTENTION' <<<"$policy_tsv"
if grep -Eq 'SYNTHETIC_POLICY_TOKEN|canary' <<<"$policy_tsv"; then echo "strict policy TSV leaked an identifier or value" >&2; exit 1; fi
echo "desktop policy TSV contract: OK"
chmod 666 "$policy_file"
if "$binary" run --policy "$policy_file" -- true >/dev/null 2>&1; then echo "writable policy file accepted" >&2; exit 1; fi
chmod 600 "$policy_file"
ln -s "$policy_file" "$policy_dir/policy-link"
if "$binary" run --policy "$policy_dir/policy-link" -- true >/dev/null 2>&1; then echo "policy symlink accepted" >&2; exit 1; fi
head -c 65537 /dev/zero >"$policy_dir/oversized.policy"
chmod 600 "$policy_dir/oversized.policy"
if "$binary" run --policy "$policy_dir/oversized.policy" -- true >/dev/null 2>&1; then echo "oversized policy accepted" >&2; exit 1; fi
mkfifo "$policy_dir/policy-fifo"
set +e
timeout 2 "$binary" run --policy "$policy_dir/policy-fifo" -- true >/dev/null 2>&1
fifo_policy_code=$?
set -e
if test "$fifo_policy_code" -eq 0 || test "$fifo_policy_code" -eq 124; then echo "policy FIFO was accepted or blocked" >&2; exit 1; fi
rm -rf "$policy_dir"
echo "secure policy and explicit approval controls: OK"
