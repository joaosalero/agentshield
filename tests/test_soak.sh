#!/usr/bin/env bash
set -euo pipefail
binary="${1:?AgentShield binary required}"
seconds="${AGENTSHIELD_SOAK_SECONDS:-10}"
case "$seconds" in (*[!0-9]*|'') echo "invalid soak duration" >&2; exit 2;; esac
if (( seconds < 2 || seconds > 3600 )); then
  echo "soak duration must be between 2 and 3600 seconds" >&2
  exit 2
fi
tmp="$(mktemp -d)"
target_pid=""
monitor_pid=""
cleanup() {
  [[ -n "$monitor_pid" ]] && kill "$monitor_pid" 2>/dev/null || true
  [[ -n "$target_pid" ]] && kill "$target_pid" 2>/dev/null || true
  rm -rf "$tmp"
}
trap cleanup EXIT INT TERM
AGENTSHIELD_SOAK_SECRET=never-emit-this-value sleep "$((seconds + 10))" &
target_pid=$!
"$binary" watch "$target_pid" --interval 50 --privacy strict >"$tmp/events.jsonl" 2>"$tmp/error.log" &
monitor_pid=$!
max_rss=0
deadline=$((SECONDS + seconds))
while (( SECONDS < deadline )); do
  if ! kill -0 "$monitor_pid" 2>/dev/null; then
    wait "$monitor_pid" || true
    echo "monitor exited during soak" >&2
    sed -n '1,20p' "$tmp/error.log" >&2
    exit 1
  fi
  rss="$(awk '/^VmRSS:/ {print $2}' "/proc/$monitor_pid/status" 2>/dev/null || echo 0)"
  (( rss > max_rss )) && max_rss=$rss
  sleep 0.2
done
kill "$monitor_pid"
wait "$monitor_pid" || true
monitor_pid=""
lines="$(wc -l < "$tmp/events.jsonl")"
if (( lines < 10 )); then
  echo "soak produced too few snapshots: $lines" >&2
  exit 1
fi
if grep -Fq 'never-emit-this-value' "$tmp/events.jsonl" "$tmp/error.log"; then
  echo "credential value leaked during soak" >&2
  exit 1
fi
if (( max_rss > 131072 )); then
  echo "monitor exceeded 128 MiB RSS during soak: ${max_rss} KiB" >&2
  exit 1
fi
echo "soak: OK ($lines snapshots, peak RSS ${max_rss} KiB)"
